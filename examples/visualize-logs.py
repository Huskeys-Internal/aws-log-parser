#!/bin/env python

import os
import sys
from collections import Counter
from pathlib import Path

# Add the parent directory to the Python path to import aws_log_parser
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from aws_log_parser import AwsLogParser, LogType

# Load environment variables from .env file
dotenv.load_dotenv(override=True)

# Configuration from environment variables
S3_PATH = os.getenv("S3_URL")
ROLE_ARN = os.getenv("1_ARN_CLOUDFORMATION")
LOG_TYPE = LogType.WAF  # Changed to WAF logs
LIMIT = 10
FILE_SUFFIX = ".log.gz"  # Updated suffix for WAF logs
VERBOSE = True  # Set to True to see more details

console = Console()

def visualize_user_agents(entries, limit=10):
    """Display top user agents in a rich table"""
    counter = Counter()
    for entry in entries:
        # For WAF logs, user agent is in the headers
        if hasattr(entry, 'httpRequest') and hasattr(entry.httpRequest, 'headers'):
            for header in entry.httpRequest.headers:
                if header.name.lower() == 'user-agent':
                    counter[header.value] += 1
                    break
    
    table = Table(title=f"Top {limit} User Agents", show_header=True)
    table.add_column("Rank", justify="right", style="cyan")
    table.add_column("User Agent", style="green")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No user agent data found in logs[/yellow]")
        return
    
    for i, (agent, count) in enumerate(counter.most_common(limit), 1):
        # Truncate very long user agent strings
        display_agent = agent if len(agent) < 80 else f"{agent[:77]}..."
        table.add_row(
            str(i),
            display_agent,
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def visualize_http_methods(entries):
    """Display HTTP methods usage in a rich table"""
    counter = Counter()
    for entry in entries:
        # For WAF logs, method is in httpRequest
        if hasattr(entry, 'httpRequest') and hasattr(entry.httpRequest, 'httpMethod'):
            counter[entry.httpRequest.httpMethod] += 1
    
    table = Table(title="HTTP Methods", show_header=True)
    table.add_column("Method", style="blue")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No HTTP method data found in logs[/yellow]")
        return
    
    for method, count in sorted(counter.items(), key=lambda x: x[1], reverse=True):
        table.add_row(
            method,
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def visualize_actions(entries):
    """Display WAF actions in a rich table"""
    counter = Counter()
    for entry in entries:
        if hasattr(entry, 'action'):
            counter[entry.action] += 1
    
    table = Table(title="WAF Actions", show_header=True)
    table.add_column("Action", style="blue")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No action data found in logs[/yellow]")
        return
    
    # Define action colors
    action_colors = {
        "ALLOW": "green",
        "BLOCK": "red",
        "COUNT": "yellow",
        "CAPTCHA": "blue",
        "CHALLENGE": "magenta"
    }
    
    for action, count in sorted(counter.items(), key=lambda x: x[1], reverse=True):
        color = action_colors.get(action, "white")
        table.add_row(
            f"[{color}]{action}[/{color}]",
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def visualize_client_ips(entries, limit=10):
    """Display top client IPs in a rich table"""
    counter = Counter()
    for entry in entries:
        # For WAF logs, client IP is in httpRequest
        if hasattr(entry, 'httpRequest') and hasattr(entry.httpRequest, 'clientIp'):
            counter[entry.httpRequest.clientIp] += 1
    
    table = Table(title=f"Top {limit} Client IPs", show_header=True)
    table.add_column("Rank", justify="right", style="cyan")
    table.add_column("IP Address", style="green")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No client IP data found in logs[/yellow]")
        return
    
    for i, (ip, count) in enumerate(counter.most_common(limit), 1):
        table.add_row(
            str(i),
            ip,
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def visualize_countries(entries, limit=10):
    """Display top countries in a rich table"""
    counter = Counter()
    for entry in entries:
        # For WAF logs, country is in httpRequest
        if hasattr(entry, 'httpRequest') and hasattr(entry.httpRequest, 'country'):
            counter[entry.httpRequest.country] += 1
    
    table = Table(title=f"Top {limit} Countries", show_header=True)
    table.add_column("Rank", justify="right", style="cyan")
    table.add_column("Country", style="green")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No country data found in logs[/yellow]")
        return
    
    for i, (country, count) in enumerate(counter.most_common(limit), 1):
        table.add_row(
            str(i),
            country if country else "Unknown",
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def visualize_hosts(entries, limit=10):
    """Display top hosts in a rich table (similar to count-hosts functionality)"""
    counter = Counter()
    for entry in entries:
        # For WAF logs, host is in the headers
        if hasattr(entry, 'httpRequest') and hasattr(entry.httpRequest, 'headers'):
            for header in entry.httpRequest.headers:
                if header.name.lower() == 'host':
                    counter[header.value] += 1
                    break
    
    table = Table(title=f"Top {limit} Hosts", show_header=True)
    table.add_column("Rank", justify="right", style="cyan")
    table.add_column("Host", style="green")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No host data found in logs[/yellow]")
        return
    
    for i, (host, count) in enumerate(counter.most_common(limit), 1):
        table.add_row(
            str(i),
            host,
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def visualize_uris(entries, limit=10):
    """Display top URIs in a rich table"""
    counter = Counter()
    for entry in entries:
        if hasattr(entry, 'httpRequest') and hasattr(entry.httpRequest, 'uri'):
            # Simplify URI by removing query parameters
            uri = entry.httpRequest.uri.split('?')[0]
            counter[uri] += 1
    
    table = Table(title=f"Top {limit} URIs", show_header=True)
    table.add_column("Rank", justify="right", style="cyan")
    table.add_column("URI", style="green")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Percentage", justify="right")
    
    total = sum(counter.values())
    if total == 0:
        console.print("[yellow]No URI data found in logs[/yellow]")
        return
    
    for i, (uri, count) in enumerate(counter.most_common(limit), 1):
        # Truncate very long URIs
        display_uri = uri if len(uri) < 80 else f"{uri[:77]}..."
        table.add_row(
            str(i),
            display_uri,
            f"{count:,}",
            f"{count/total:.2%}"
        )
    
    console.print(table)

def main():
    if not S3_PATH:
        console.print("[bold red]Error:[/bold red] S3_URL not found in .env file")
        return
    
    if not ROLE_ARN:
        console.print("[bold yellow]Warning:[/bold yellow] 1_ARN_CLOUDFORMATION not found in .env file. Running without role assumption.")
    
    console.print(Panel.fit(
        f"[bold blue]AWS Log Visualizer[/bold blue]\n"
        f"Log Type: [green]{LOG_TYPE.name}[/green]\n"
        f"Source: [yellow]{S3_PATH}[/yellow]"
    ))
    
    # Create progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[bold blue]Loading and parsing logs...", total=None)
        
        # Parse logs with role assumption
        log_parser = AwsLogParser(
            log_type=LOG_TYPE,
            role_arn=ROLE_ARN,
            role_session_name="aws-log-parser-session",
            verbose=VERBOSE,
            file_suffix=FILE_SUFFIX,
        )
        
        try:
            # Convert generator to list to process multiple times
            entries = list(log_parser.read_url(S3_PATH))
            progress.update(task, description="[bold green]Logs loaded successfully!")
            
            console.print(f"\n[bold]Analyzed [cyan]{len(entries):,}[/cyan] log entries[/bold]\n")
            
            # Display host information (count-hosts functionality)
            visualize_hosts(entries, LIMIT)
            console.print()
            
            # Display URI information
            visualize_uris(entries, LIMIT)
            console.print()
            
            # Display visualizations
            visualize_user_agents(entries, LIMIT)
            console.print()
            
            visualize_http_methods(entries)
            console.print()
            
            visualize_actions(entries)  # WAF-specific visualization
            console.print()
            
            visualize_client_ips(entries, LIMIT)
            console.print()
            
            visualize_countries(entries, LIMIT)  # WAF-specific visualization
            
        except Exception as e:
            progress.update(task, description=f"[bold red]Error: {str(e)}")
            console.print(f"\n[bold red]Failed to process logs: {str(e)}[/bold red]")
            raise


if __name__ == "__main__":
    main() 