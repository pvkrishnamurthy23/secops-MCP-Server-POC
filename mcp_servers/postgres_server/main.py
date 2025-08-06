from fastmcp import FastMCP
import psycopg2
import pandas as pd
import openai
import re
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.chat_models import ChatOpenAI
from langchain.schema import HumanMessage
import boto3
from botocore.exceptions import ClientError
from Utils.logger import logger


def get_secret():

    secret_name = "ipl/secops/db/openai"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
       
        raise e

    return get_secret_value_response

# Load secrets once at startup
secrets = get_secret()

openai.api_key = secrets['OPENAI_API_KEY']

app = FastMCP()



def get_connection():
    return psycopg2.connect(secrets['DATABASE_URL'])

def sql_query(query: str):
    """Execute a SQL query and return the results as a list of dicts."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            if cur.description is None:
                return []
            colnames = [desc[0] for desc in cur.description]
            return [dict(zip(colnames, row)) for row in rows]

@app.tool
def SecurityReportSummaryTool(query: str):
    """Generates security summary of the environment. uses the Prowler report, pus data from it and generates a summary out of it"""

    sql_queries = {
        "overall_posture": """
            SELECT 
                COUNT(*) AS total_checks,
                COUNT(*) FILTER (WHERE status = 'PASS') AS passed,
                COUNT(*) FILTER (WHERE status = 'FAIL') AS failed,
                ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'PASS') / COUNT(*), 2) AS pass_rate_percent
            FROM findings;
        """,

        "severity_breakdown": """
            SELECT 
                severity,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'FAIL') AS failed,
                ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'FAIL') / COUNT(*), 2) AS fail_rate_percent
            FROM findings
            GROUP BY severity
            ORDER BY failed DESC;
        """,

        "failing_services": """
            SELECT 
                service_name,
                COUNT(*) FILTER (WHERE status = 'FAIL') AS failed_checks
            FROM findings
            GROUP BY service_name
            ORDER BY failed_checks DESC
            LIMIT 10;
        """,

        "top_failing_checks": """
            SELECT 
                check_id,
                check_title,
                COUNT(*) AS failure_count
            FROM findings
            WHERE status = 'FAIL'
            GROUP BY check_id, check_title
            ORDER BY failure_count DESC
            LIMIT 10;
        """,

        
        "region_failures": """
            SELECT 
                region,
                COUNT(*) FILTER (WHERE status = 'FAIL') AS failed_checks
            FROM findings
            GROUP BY region
            ORDER BY failed_checks DESC;
        """ 
    }

    results = {}
    for key, sql in sql_queries.items():
        rows = sql_query(sql) 
        df = pd.DataFrame(rows)
        if df.empty:
            results[key] = "No data found."
        else:
            preview = df.head(10).to_markdown(index=False)
            logger.info(f"Preview for {key}:\n{preview}")
            summary_prompt = f"Here is the result from prowler scan:\n\n{preview}\n\nSummarize the insight this table reveals."
            summary_response = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{'role': 'user', 'content': summary_prompt}]
            )
            results[key] = summary_response.choices[0].message.content.strip()

    # Compile all into one report
    final_summary = "# 📊 Prowler Report Executive Summary\n\n"
    sections = {
        "overall_posture": "##  Overall Security Posture",
        "severity_breakdown": "##  Severity Distribution",
        "failing_services": "##  Services with Most Failures",
        "top_failing_checks": "##  Most Common Failing Checks",
        "region_failures": "##  Regional Risk Overview"
    }

    for key, title in sections.items():
        final_summary += f"{title}\n{results.get(key, 'No data.')}\n\n"
    logger.info(f"Final summary generated:\n{final_summary}")
    return final_summary





@app.tool
def FindingsInterpreterTool(query: str):
    """Convert a natural language question to a PostgreSQL SQL query for the findings table, execute it, and summarize the result."""
    system_prompt = (
        "You are a helpful data analyst. "
        "Table name is 'findings'. "
        "The database consists of plowler reports on AWS account and its findings"
        "restrict the number of results to 10 for all queries"
        "column names are  assessment_start_time,finding_unique_id,provider, check_id, check_title, check_type, status, status_extended, service_name, subservice_name, severity, resource_type, resource_details, resource_tags, description, risk, related_url, remediation_recommendation_text, remediation_recommendation_url, remediation_recommendation_code_nativeiac, remediation_recommendation_code_terraform, remediation_recommendation_code_cli, remediation_recommendation_code_other, compliance, categories, depends_on, related_to, notes, profile, account_id, account_name, account_email, account_arn, account_org, account_tags, region, resource_id, resource_arn"
        "Status has 2 values PASS and FAIL. add values to query accordingly"
        "severity has 4 values medium, critical, high, low. add values to query accordingly"
        "service_name has following values cloudformation, fms, config, support, backup, resourceexplorer2, ec2, cloudtrail, s3, account, lambda, apigateway, cloudwatch, ssm, accessanalyzer, autoscaling, iam, vpc, acm, athena, trustedadvisor"
        "Given the above database schema, generate a valid PostgreSQL SQL query to answer the user's question. "
        "Return only SQL. and nothing else. Don't explain.\n\n"
    )
    full_prompt = f"{system_prompt}\nUser: {query}"
    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{'role': 'user', 'content': full_prompt}]
    )
    sql_response = response.choices[0].message.content
    # Extract SQL code block if present
    sql_match = re.search(r"```sql(.*?)```", sql_response or "", re.DOTALL | re.IGNORECASE)
    if sql_match:
        generated_sql = sql_match.group(1).strip()
    else:
        generated_sql = (sql_response or "").strip('`').strip()
    logger.debug(f"Generated SQL: {generated_sql}")
    rows = sql_query(generated_sql)
    df = pd.DataFrame(rows)
    if df.empty:
        return "No results found for your query."
    preview = df.head(10).to_markdown(index=False)
    summary_prompt = f"Here is the SQL result table:\n\n{preview}\n\n take the content from the result and summarize it."
    summary_response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{'role': 'user', 'content': summary_prompt}]
    )
    summary = summary_response.choices[0].message.content
    logger.debug(f"Summary type: {type(summary)}")
    logger.info(f"Summary: {summary}")
    return summary





CHROMA_DB_DIR = "chroma_db"
COLLECTION_NAME = "website_content"
OPENAI_MODEL = "gpt-4o-mini"  

# Initialize embeddings and vector store
def init_vector_store():
    api_key = secrets['OPENAI_API_KEY']
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set in AWS Secrets Manager")

    embeddings = OpenAIEmbeddings(
        model="text-embedding-ada-002",
        chunk_size=1,
        openai_api_key=api_key
    )

    vectordb = Chroma(
        persist_directory=CHROMA_DB_DIR,
        embedding_function=embeddings,
        collection_name=COLLECTION_NAME
    )
    return vectordb

# Search vector DB and get top-k chunks
def retrieve_context(vectordb, query, k=5):
    return vectordb.similarity_search(query, k=k)

# Compose a long-form answer using OpenAI's GPT model
def generate_answer(query, context_docs):
    api_key = secrets['OPENAI_API_KEY']
    llm = ChatOpenAI(openai_api_key=api_key, model=OPENAI_MODEL)

    # Concatenate the retrieved context
    context_text = "\n\n---\n\n".join(doc.page_content for doc in context_docs)

    prompt = f"""You are a helpful assistant. Use the below retrieved content to answer the user's query in detail output only in valid string format.

### Retrieved Content:
{context_text}

### User Query:
{query}

### Answer:
"""
    response = llm([HumanMessage(content=prompt)])
    return response.content




@app.tool
def PlatformWebSearchTool(query: str):
    """Search a single website for a query using Tavily and return the result."""
    query = query
    if query:
        
        try:
            vectordb = init_vector_store()
            docs = retrieve_context(vectordb, query)
            if not docs:
                return f"No relevant documents found."
            else:
                                        
                answer = generate_answer(query, docs)
                return(answer)
        except Exception as e:
            return f"Web search error: {e}"
        

@app.tool
def RemediationSuggesterTool(query: str):
    """Generate remediation steps or a custom script for a specific cloud misconfiguration using OpenAI."""
    prompt = (
        f"A user has reported the following cloud misconfiguration: '{query}'.\n"
        "Provide a step-by-step remediation plan or a custom script or terraform script to fix this issue. "
        "If a script is appropriate, provide it in a code block. Be concise, accurate, and actionable."
    )
    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{'role': 'user', 'content': prompt}]
    )
    return response.choices[0].message.content

if __name__ == '__main__':
    logger.info("Starting FastMCP server on http://127.0.0.1:8000/mcp")
    app.run(transport='streamable-http', host='127.0.0.1', port=8000)