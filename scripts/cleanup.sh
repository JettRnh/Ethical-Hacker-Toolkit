#!/bin/bash
# Cleanup script for Ethical Hacker Toolkit
# Removes old reports and logs to free disk space
# Author: Jet
# GitHub: https://github.com/JettRnh

echo "Ethical Hacker Toolkit - Cleanup Utility"
echo "========================================"
echo ""

REPORTS_DIR="reports"
LOGS_DIR="logs"

# Check directories exist
if [ ! -d "$REPORTS_DIR" ] && [ ! -d "$LOGS_DIR" ]; then
    echo "No reports or logs directories found."
    exit 0
fi

# Display current usage
echo "Current disk usage:"
if [ -d "$REPORTS_DIR" ]; then
    REPORTS_SIZE=$(du -sh "$REPORTS_DIR" 2>/dev/null | cut -f1)
    REPORTS_COUNT=$(find "$REPORTS_DIR" -type f -name "*.txt" -o -name "*.json" -o -name "*.html" 2>/dev/null | wc -l)
    echo "  Reports: $REPORTS_SIZE ($REPORTS_COUNT files)"
fi

if [ -d "$LOGS_DIR" ]; then
    LOGS_SIZE=$(du -sh "$LOGS_DIR" 2>/dev/null | cut -f1)
    LOGS_COUNT=$(find "$LOGS_DIR" -type f -name "*.log" 2>/dev/null | wc -l)
    echo "  Logs: $LOGS_SIZE ($LOGS_COUNT files)"
fi

echo ""
echo "Options:"
echo "  1. Delete reports older than 30 days"
echo "  2. Delete all reports"
echo "  3. Delete logs older than 30 days"
echo "  4. Delete all logs"
echo "  5. Delete all reports and logs"
echo "  6. Exit"
echo ""

read -p "Select option [1-6]: " OPTION

case $OPTION in
    1)
        echo "Deleting reports older than 30 days..."
        find "$REPORTS_DIR" -type f \( -name "*.txt" -o -name "*.json" -o -name "*.html" \) -mtime +30 -delete
        echo "Done."
        ;;
    2)
        echo "Deleting all reports..."
        rm -f "$REPORTS_DIR"/*.txt "$REPORTS_DIR"/*.json "$REPORTS_DIR"/*.html 2>/dev/null
        echo "Done."
        ;;
    3)
        echo "Deleting logs older than 30 days..."
        find "$LOGS_DIR" -type f -name "*.log" -mtime +30 -delete
        echo "Done."
        ;;
    4)
        echo "Deleting all logs..."
        rm -f "$LOGS_DIR"/*.log 2>/dev/null
        echo "Done."
        ;;
    5)
        echo "Deleting all reports and logs..."
        rm -f "$REPORTS_DIR"/*.txt "$REPORTS_DIR"/*.json "$REPORTS_DIR"/*.html 2>/dev/null
        rm -f "$LOGS_DIR"/*.log 2>/dev/null
        echo "Done."
        ;;
    6)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo "Invalid option."
        exit 1
        ;;
esac

echo ""
echo "Cleanup completed."
