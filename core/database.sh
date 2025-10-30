#!/bin/bash
#
# Database Management
# Initialize and manage all database files
#

# Initialize credential database
init_creds_db() {
    if [[ ! -f "$CREDS_DB" ]]; then
        cat > "$CREDS_DB" << 'EOF'
# NXC Credentials Database
# Format: NAME|USERNAME|PASSWORD|DOMAIN|HASH
Null Auth|''|''||
Guest Account|guest|''||
EOF
        chmod 600 "$CREDS_DB"
    fi
}

# Initialize targets database
init_targets_db() {
    if [[ ! -f "$TARGETS_DB" ]]; then
        cat > "$TARGETS_DB" << 'EOF'
# NXC Targets Database
# Format: NAME|TARGET
EOF
        chmod 600 "$TARGETS_DB"
    fi
}

# Initialize web targets database
init_web_targets_db() {
    if [[ ! -f "$WEB_TARGETS_DB" ]]; then
        cat > "$WEB_TARGETS_DB" << 'EOF'
# Web Targets Database
# Format: NAME|URL
EOF
        chmod 600 "$WEB_TARGETS_DB"
    fi
}

# Initialize AD targets database
init_ad_targets_db() {
    if [[ ! -f "$AD_TARGETS_DB" ]]; then
        cat > "$AD_TARGETS_DB" << 'EOF'
# Active Directory Targets Database
# Format: NAME|DOMAIN|DC_NAME|DC_IP|ADDITIONAL_INFO
EOF
        chmod 600 "$AD_TARGETS_DB"
    fi
}

# Initialize nmap results directory
init_nmap_results_dir() {
    if [[ ! -d "$NMAP_RESULTS_DIR" ]]; then
        mkdir -p "$NMAP_RESULTS_DIR"
        chmod 700 "$NMAP_RESULTS_DIR"
    fi
}

# Initialize all databases
init_all_databases() {
    init_creds_db
    init_targets_db
    init_web_targets_db
    init_ad_targets_db
    init_nmap_results_dir
}
