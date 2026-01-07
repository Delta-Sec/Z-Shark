import argparse
from pathlib import Path
from loguru import logger
import json
import sys

from zshark.core import Analyzer, ZSharkConfig, AnalysisResult
from zshark.reports.pdf_generator import generate_pdf_report

def setup_logging(verbose: bool):
    logger.remove()
    level = "DEBUG" if verbose else "INFO"

    logger.add(sys.stderr, level=level, format="<green>{time:HH:mm:ss}</green> | {level} | {message}")

def analyze_command(args):
    setup_logging(args.verbose)
    
    try:
        pcap_path = Path(args.pcap_path)
        out_dir = Path(args.out_dir)
        
        if not pcap_path.exists():
            logger.error(f"PCAP file not found: {pcap_path}")
            sys.exit(1)

        out_dir.mkdir(parents=True, exist_ok=True)
        
        config = ZSharkConfig.default()
        config.analysis_profile = args.profile
        config.output_dir = str(out_dir)
        config.parallel_workers = args.parallel
        
        logger.info(f"Starting analysis of {pcap_path.name} with profile '{args.profile}'...")
        
        analyzer = Analyzer(config)
        result: AnalysisResult = analyzer.analyze_pcap(str(pcap_path))
        
        output_path = out_dir / f"{pcap_path.stem}_analysis.json"
        with open(output_path, "w") as f:
            f.write(result.model_dump_json(indent=4))
            
        logger.success(f"Analysis complete. Results saved to {output_path}")
        print(f"Total Detections: {len(result.detections)}")
        
    except Exception as e:
        logger.error(f"An error occurred during analysis: {e}")
        sys.exit(1)

def report_command(args):
    setup_logging(args.verbose)
    
    try:
        analysis_json_path = Path(args.analysis_json_path)
        pdf_path = Path(args.pdf_path)
        
        if not analysis_json_path.exists():
            logger.error(f"Analysis JSON file not found: {analysis_json_path}")
            sys.exit(1)

        logger.info(f"Generating PDF report from {analysis_json_path.name}...")
        
        generate_pdf_report(str(analysis_json_path), str(pdf_path))
        logger.success(f"PDF report successfully generated and saved to {pdf_path}")
    except Exception as e:
        logger.error(f"An error occurred during report generation: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="zshark",
        description="Z-Shark: The World-Class Packet Analysis Platform.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    analyze_parser = subparsers.add_parser("analyze", help="Analyzes a PCAP file using mathematical models.")
    analyze_parser.add_argument("pcap_path", type=str, help="Path to the PCAP file to analyze.")
    analyze_parser.add_argument("-o", "--out-dir", type=str, default="results", help="Output directory for analysis results (default: results).")
    analyze_parser.add_argument("-p", "--profile", type=str, default="default", help="Analysis profile to use (default: default).")
    analyze_parser.add_argument("--parallel", type=int, default=1, help="Number of parallel workers (default: 1).")
    analyze_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    analyze_parser.set_defaults(func=analyze_command)

    report_parser = subparsers.add_parser("report", help="Generates a PDF report from a saved analysis result.")
    report_parser.add_argument("analysis_json_path", type=str, help="Path to the analysis JSON file.")
    report_parser.add_argument("-o", "--pdf-path", type=str, default="report.pdf", help="Output path for the generated PDF report (default: report.pdf).")
    report_parser.add_argument("-t", "--template", type=str, default="forensic", help="Report template to use (default: forensic).")
    report_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    report_parser.set_defaults(func=report_command)

    subparsers.add_parser("summary", help="Provides a quick statistical summary of a PCAP file (Placeholder).")
    subparsers.add_parser("serve", help="Starts the Z-Shark web service (Placeholder).")
    subparsers.add_parser("train", help="Trains optional AI/ML models (Placeholder).")
    subparsers.add_parser("replay", help="Replays a PCAP file to a network interface (Placeholder).")

    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
