#!/bin/bash
#
# NXC LDAP Module
# LDAP Enumeration and BloodHound Collection Functions
#
# This module requires the following functions from main script:
# - build_auth()
# - get_target_for_command()
# - run_command()
# - show_menu()
#
# Required global variables:
# - DOMAIN, USERNAME, PASSWORD, HASH, TARGET
# - RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, NC (colors)
#

# Handle LDAP Enumeration operations
handle_ldap() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
    domain=${DOMAIN:-WORKGROUP}

    subchoice=$(show_menu "ldap" "Select LDAP Operation: ")

    case "$subchoice" in
        "Enumerate Users")
            run_command "nxc ldap $target $auth -d $domain --users"
            ;;
        "Enumerate Groups")
            run_command "nxc ldap $target $auth -d $domain --groups"
            ;;
        "Get User Descriptions")
            run_command "nxc ldap $target $auth -d $domain -M get-desc-users"
            ;;
        "Enumerate Computers")
            run_command "nxc ldap $target $auth -d $domain -M machines"
            ;;
        "Enumerate Domain Trusts")
            run_command "nxc ldap $target $auth -d $domain -M enum_trusts"
            ;;
        "ADCS Enumeration")
            run_command "nxc ldap $target $auth -d $domain -M adcs"
            ;;
        "Check LDAP Signing")
            run_command "nxc ldap $target $auth -d $domain -M ldap-checker"
            ;;
        "Get All User Attributes")
            run_command "nxc ldap $target $auth -d $domain -M user-desc"
            ;;
    esac
}

# Handle BloodHound Collection operations
handle_bloodhound() {
    auth=$(build_auth)
    target=$(get_target_for_command) || return 1
    domain=${DOMAIN:-WORKGROUP}

    subchoice=$(show_menu "bloodhound" "Select Collection: ")

    case "$subchoice" in
        "Collect All")
            run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=All"
            ;;
        "Collect Sessions")
            run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=Session"
            ;;
        "Collect Trusts")
            run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=Trusts"
            ;;
        "Collect ACL")
            run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=ACL"
            ;;
        "Collect Groups")
            run_command "nxc ldap $target $auth -d $domain -M bloodhound -o COLLECTION=Group"
            ;;
    esac
}
