#!/bin/bash
#
# Core Configuration
# Global variables, colors, and constants
#

# Database files
CREDS_DB="$HOME/.pentest-credentials.db"
TARGETS_DB="$HOME/.pentest-targets.db"
WEB_TARGETS_DB="$HOME/.pentest-web-targets.db"
AD_TARGETS_DB="$HOME/.pentest-ad-targets.db"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Current selections
CURRENT_CRED_NAME=""
CURRENT_TARGET_NAME=""
USERNAME=""
PASSWORD=""
DOMAIN=""
HASH=""
TARGET=""
RUN_MODE="single"  # single or all

# Web target selections
CURRENT_WEB_TARGET=""
WEB_TARGET_URL=""

# AD Target selections
CURRENT_AD_TARGET_NAME=""
AD_DOMAIN=""
AD_DC_NAME=""
AD_DC_IP=""
AD_ADDITIONAL_INFO=""
