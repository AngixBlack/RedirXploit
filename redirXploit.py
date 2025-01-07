#!/usr/bin/python3

import argparse
import requests
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.logging import RichHandler
import logging
import sys
from rich import box 

console = Console()

#  logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger("rich")

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "javascript:alert(1)",
    "%2F%2Fevil.com"
]



def print_logo():
    
    console.print("\n" * 3, end="")  

    
    subtitle = "[bold magenta]RedirXploit: Open Redirect Scanner[/bold magenta]"
    credit = "[bold green]Coded By Angix Black[/bold green]"
    disclaimer = "[bold red]Disclaimer: Use this tool ethically. The creator is not responsible for illegal use.[/bold red]"

    content = f"{subtitle}\n\n{credit}\n\n{disclaimer}"

    
    console.print(Panel(
        content,
        border_style="bold",
        title="[bold yellow]RedirXploit[/bold yellow]",
        title_align="center",
        padding=1,  
        expand=False
    ))


def is_valid_url(url):
    """Check if the URL well-formed"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_vulnerable(url, param, payload):
    """Check if the parameter is vulnerable by injecting a payload."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = payload
    modified_query = urlencode(query_params, doseq=True)
    modified_url = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, modified_query, parsed_url.fragment)
    )

    if not is_valid_url(modified_url):
        console.print(f"[bold yellow]Skipping invalid URL:[/bold yellow] {modified_url}")
        return False

    try:
        response = requests.get(modified_url, allow_redirects=True, timeout=10)
        if payload in response.url:
            return True
    except requests.RequestException as e:
        console.print(f"[bold red]Error scanning {url}:[/bold red] {e}")
    return False

def scan_url(url):
    """Scan a single URL """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    vulnerabilities = []

    for param in query_params:
        for payload in REDIRECT_PAYLOADS:
            if is_vulnerable(url, param, payload):
                vulnerabilities.append((param, payload))
                break  # Stop testing 
    return vulnerabilities

def scan_file(file_path, threads):
    """Scan URLs from a file """
    try:
        with open(file_path, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        console.print(f"[bold red]File {file_path} not found.[/bold red]")
        return []

    results = []

    with Progress(
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Scanning URLs", total=len(urls))

        def worker(url):
            try:
                console.print(f"[cyan]Scanning URL:[/cyan] {url}")
                vulnerabilities = scan_url(url)
                results.append((url, vulnerabilities))
                progress.advance(task)
            except KeyboardInterrupt:
                console.print(f"\n[bold red]Scan interrupted for {url}[/bold red]")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(worker, url): url for url in urls}

            try:
                for future in as_completed(future_to_url):
                    future.result()
            except KeyboardInterrupt:
                console.print(f"\n[bold red]Scan interrupted by the user. Exiting...[/bold red]")
                executor.shutdown(wait=False, cancel_futures=True)

    return results

def display_vulnerabilities(url, vulnerabilities):
    """Display vulnerabilities in a table."""
    if vulnerabilities:
        table = Table(title=f"[red bold]Vulnerabilities Found for {url}[/red bold]")
        table.add_column("Parameter", style="bold yellow")
        table.add_column("Payload", style="bold cyan")
        for param, payload in vulnerabilities:
            table.add_row(param, payload)
        console.print(table)
    else:
        console.print(f"[bold green][SAFE] No vulnerabilities found for {url}.[/bold green]")

def display_summary(results):
    """Display a summary of scan results """
    total = len(results)
    vulnerable = sum(1 for url, vulns in results if vulns)
    safe = total - vulnerable

    vulnerable_urls = [url for url, vulns in results if vulns]

    console.print(Panel.fit(
        f"[bold green]Scan Summary[/bold green]\n"
        f"[bold yellow]Total URLs:[/bold yellow] {total}\n"
        f"[bold red]Vulnerable URLs:[/bold red] {vulnerable}\n"
        f"[bold green]Safe URLs:[/bold green] {safe}",
        title="[cyan bold]Results Summary[/cyan bold]"
    ))

    if vulnerable_urls:
        console.print("[bold red]Vulnerable URLs:[/bold red]")
        for url in vulnerable_urls:
            console.print(f"[bold yellow] {url} [/bold yellow]")

def export_results(results, output_file):
    """Export JSON file."""
    try:
        formatted_results = {
            url: [{"parameter": param, "payload": payload} for param, payload in vulns]
            for url, vulns in results if vulns
        }
        with open(output_file, "w") as file:
            json.dump(formatted_results, file, indent=4)
        console.print(f"[bold green]Results exported to {output_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to export results: {e}[/bold red]")

def display_help_menu():
    table = Table(title="[bold cyan]Help Menu - RedirXploit[/bold cyan]", box=box.ROUNDED)
    table.add_column("Argument", style="bold green", justify="center", width=15)
    table.add_column("Description", style="bold yellow", justify="left")

    table.add_row("[bold cyan]-u, --url[/bold cyan]", "Scan a single URL for vulnerabilities.")
    table.add_row("[bold cyan]-f, --file[/bold cyan]", "Provide a file containing multiple URLs to scan.")
    table.add_row("[bold cyan]-t, --threads[/bold cyan]", "Set the number of threads for file scanning (default: 10).")
    table.add_row("[bold cyan]-o, --output[/bold cyan]", "Specify an output file to save results in JSON format.")
    table.add_row("[bold cyan]-p, --payloads[/bold cyan]", "Provide a file containing custom payloads for the scan.")

    console.print(table)
    console.print(
        Panel(
            "[bold white]Usage Examples:[/bold white]\n"
            "[green] redirx -u https://example.com[/green]\n"
            "[green] redirx -f urls.txt -t 20 -o results.json[/green]",
            title="[bold yellow]Usage[/bold yellow]",
            style="bold cyan",
            width=70,
        )
    )


def validate_args(args):
    """Validate arguments and show help if there are issues."""
    if not (args.url or args.file):
        console.print(f"[bold red]Error:[/bold red] You must provide either a URL or a file to scan.")
        display_help_menu()
        sys.exit(1)

    if args.url and not is_valid_url(args.url):
        console.print(f"[bold red]Error:[/bold red] The provided URL is invalid.")
        display_help_menu()
        sys.exit(1)

    if args.file and not args.file.endswith(".txt"):
        console.print(f"[bold red]Error:[/bold red] The file must be a text file (.txt).")
        display_help_menu()
        sys.exit(1)

def main():
    print_logo()
    parser = argparse.ArgumentParser(
        description="Open Redirect Vulnerability Scanner",
        add_help=False
    )
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-f", "--file", help="File containing URLs to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for file scanning (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save results in JSON format")
    parser.add_argument("-p", "--payloads", help="File containing custom payloads")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help menu")

    args = parser.parse_args()

    if args.help:
        display_help_menu()
        sys.exit(0)

    if args.payloads:
        try:
            with open(args.payloads, "r") as file:
                global REDIRECT_PAYLOADS
                REDIRECT_PAYLOADS = file.read().splitlines()
            console.print("[bold green]Custom payloads loaded.[/bold green]")
        except FileNotFoundError:
            console.print(f"[bold red]Payload file {args.payloads} not found.[/bold red]")

    results = []

    try:
        validate_args(args)

        if args.url:
            console.print(f"[cyan]Scanning URL: {args.url}[/cyan]")
            vulnerabilities = scan_url(args.url)
            if vulnerabilities:
                console.print(f"[bold red][VULNERABLE][/bold red] Found issues:")
                display_vulnerabilities(args.url, vulnerabilities)
            else:
                console.print(f"[bold green][SAFE] No vulnerabilities found.[/bold green]")
        elif args.file:
            results = scan_file(args.file, args.threads)
            display_summary(results)

        if args.output:
            export_results(results, args.output)
        else:
            console.print("[bold yellow]No output file specified.[/bold yellow]")

    except KeyboardInterrupt:
        console.print(f"\n[bold red]Scan interrupted by the user. Exiting...[/bold red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
