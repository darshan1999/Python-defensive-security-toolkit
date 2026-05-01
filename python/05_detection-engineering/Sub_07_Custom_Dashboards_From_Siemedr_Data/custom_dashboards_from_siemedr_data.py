"""
Custom Dashboards From Siemedr Data

Security operations automation tool.
"""

# app.py
from datetime import datetime
from elasticsearch import Elasticsearch
from dash import Dash, dcc, html, Input, Output
import plotly.express as px
import pandas as pd
# 3.1 Data Retrieval: connect to Elasticsearch
es = Elasticsearch(
    ["https://es.example.com:9200"],
    http_auth=("elastic", "changeme"),
    scheme="https",
    port=9200
)
def query_failed_logins(start_time, end_time):
    """
    Query Elasticsearch for count of failed logins per source IP
    between start_time and end_time.
    Returns a pandas DataFrame.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "failed_login"}},
                    {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
                ]
            }
        },
        "aggs": {
            "by_src_ip": {
                "terms": {"field": "src_ip", "size": 10}
            }
        }
    }
    resp = es.search(index="security-logs", body=body)
    buckets = resp["aggregations"]["by_src_ip"]["buckets"]
    # Build DataFrame for Dash
    return pd.DataFrame({
        "src_ip": [b["key"] for b in buckets],
        "count":  [b["doc_count"] for b in buckets]
    })
# 3.2 Dash App Setup
app = Dash(__name__)
app.layout = html.Div([
    html.H1("Failed Logins Dashboard"),
    html.Div([
        html.Label("Start Time (ISO)"),
        dcc.Input(id="start-time", type="text",
                  value=(datetime.utcnow().replace(microsecond=0).isoformat() + "Z")),
        html.Label("End Time (ISO)"),
        dcc.Input(id="end-time", type="text",
                  value=(datetime.utcnow().replace(microsecond=0).isoformat() + "Z")),
        html.Button("Update", id="update-button")
    ]),
    dcc.Graph(id="failed-logins-graph")
])
# 3.3 Callback: update graph on button click
@app.callback(
    Output("failed-logins-graph", "figure"),
    Input("update-button", "n_clicks"),
    Input("start-time", "value"),
    Input("end-time", "value")
)
def update_graph(n_clicks, start_iso, end_iso):
    # Convert inputs to strings acceptable by Elasticsearch
    df = query_failed_logins(start_iso, end_iso)
    # Build a bar chart with Plotly Express
    fig = px.bar(
        df,
        x="src_ip", y="count",
        title=f"Top 10 Failed Logins from {start_iso} to {end_iso}",
        labels={"src_ip": "Source IP", "count": "Failed Login Count"}
    )
    return fig
# 3.4 Run the app
if __name__ == "__main__":
    app.run_server(host="0.0.0.0", port=8050, debug=True)
# - Separation of Concerns
# - `query_failed_logins` handles data access and transformation.
# - Dash layout and callbacks manage presentation logic.
# - Interactive Controls