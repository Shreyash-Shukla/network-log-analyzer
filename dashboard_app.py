import dash
from dash import dcc, html, Input, Output, callback
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from log_analyzer import NetworkLogAnalyzer
import dash_bootstrap_components as dbc

# Initialize the analyzer
analyzer = NetworkLogAnalyzer()

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("Network Log Analyzer Dashboard", className="text-center mb-4"),
            html.Hr()
        ])
    ]),
    
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Upload Log File", className="card-title"),
                    dcc.Upload(
                        id='upload-data',
                        children=html.Div([
                            'Drag and Drop or ',
                            html.A('Select Log File')
                        ]),
                        style={
                            'width': '100%',
                            'height': '60px',
                            'lineHeight': '60px',
                            'borderWidth': '1px',
                            'borderStyle': 'dashed',
                            'borderRadius': '5px',
                            'textAlign': 'center',
                            'margin': '10px'
                        },
                        multiple=False
                    ),
                    html.Div(id='upload-status')
                ])
            ])
        ], width=12)
    ], className="mb-4"),
    
    dbc.Row([
        dbc.Col([
            html.Div(id='analysis-content')
        ], width=12)
    ])
], fluid=True)

@callback(
    [Output('upload-status', 'children'),
     Output('analysis-content', 'children')],
    [Input('upload-data', 'contents'),
     Input('upload-data', 'filename')]
)
def update_output(contents, filename):
    if contents is None:
        return "", html.Div("Please upload a log file to begin analysis.", className="text-center text-muted")
    
    try:
        # Parse the uploaded file
        import base64
        import io
        
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        
        # Save to temporary file
        temp_filename = f"temp_{filename}"
        with open(temp_filename, 'wb') as f:
            f.write(decoded)
        
        # Run analysis
        analyzer.run_full_analysis(temp_filename)
        
        # Generate visualizations
        figs = analyzer.create_visualizations()
        report = analyzer.generate_traffic_report()
        anomalies = analyzer.anomalies
        
        # Create dashboard content
        upload_status = dbc.Alert(f"Successfully analyzed {filename}", color="success")
        
        analysis_content = [
            # Summary Statistics
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H5("Summary Statistics", className="card-title"),
                            html.P(f"Total Requests: {report['total_requests']:,}"),
                            html.P(f"Unique IPs: {report['unique_ips']:,}"),
                            html.P(f"Error Rate: {report.get('error_rate', 0):.2%}"),
                            html.P(f"Date Range: {report['date_range']['start']} to {report['date_range']['end']}")
                        ])
                    ])
                ], width=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H5("Anomalies Detected", className="card-title"),
                            html.P(f"Total Anomalies: {len(anomalies)}", 
                                  className="text-danger" if len(anomalies) > 0 else "text-success"),
                            html.Ul([
                                html.Li(f"{a['type']} - {a['severity']}") for a in anomalies[:5]
                            ]) if anomalies else html.P("No anomalies detected", className="text-success")
                        ])
                    ])
                ], width=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H5("Top Methods", className="card-title"),
                            html.Ul([
                                html.Li(f"{method}: {count:,}") 
                                for method, count in list(report.get('method_distribution', {}).items())[:5]
                            ])
                        ])
                    ])
                ], width=4)
            ], className="mb-4"),
            
            # Visualizations
            dbc.Row([
                dbc.Col([
                    html.H4("Traffic Over Time"),
                    dcc.Graph(figure=figs.get('traffic_timeline', {}))
                ], width=6),
                dbc.Col([
                    html.H4("Status Code Distribution"),
                    dcc.Graph(figure=figs.get('status_distribution', {}))
                ], width=6)
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col([
                    html.H4("Top IP Addresses"),
                    dcc.Graph(figure=figs.get('top_ips', {}))
                ], width=6),
                dbc.Col([
                    html.H4("HTTP Methods"),
                    dcc.Graph(figure=figs.get('method_distribution', {}))
                ], width=6)
            ])
        ]
        
        return upload_status, analysis_content
        
    except Exception as e:
        error_msg = dbc.Alert(f"Error analyzing file: {str(e)}", color="danger")
        return error_msg, html.Div("Analysis failed. Please check the log file format.", className="text-center text-danger")

if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)
