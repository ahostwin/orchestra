#!/bin/bash

# AHost Orchestra Client Script
# Low-dependency bash script for SSH key-based device orchestration
VERSION=1
# This script:
# 1. Finds SSH keys with "key@ahostorchestra" in the user comment
# 2. Calculates fingerprint and creates URL-safe access token
# 3. Sends token to server and executes returned script

set -euo pipefail

# Configuration
KEYWORD="key@ahostorchestra"
AUTHORIZED_KEYS="$HOME/.ssh/authorized_keys"
CLI_DIR="/tmp/orchestra"
SERVER_URL="${AHOST_SERVER_URL:-https://your-supabase-instance.supabase.co}"
TEMP_DIR=$(mktemp -d)
TEMP_KEYS="$TEMP_DIR/matching_keys"

ENDPOINT_ENROLL="functions/v1/enroll"
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

# Cleanup function
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Check if authorized_keys file exists
check_authorized_keys() {
    if [ ! -f "$AUTHORIZED_KEYS" ]; then
        error "Authorized keys file not found: $AUTHORIZED_KEYS"
        exit 1
    fi
    
    if [ ! -r "$AUTHORIZED_KEYS" ]; then
        error "Cannot read authorized keys file: $AUTHORIZED_KEYS"
        exit 1
    fi
    
    log "Found authorized keys file: $AUTHORIZED_KEYS"
}

# Find SSH keys with the specified keyword
find_matching_keys() {
    log "Searching for SSH keys with keyword: $KEYWORD"
    
    if ! grep -q "$KEYWORD" "$AUTHORIZED_KEYS" 2>/dev/null; then
        error "No SSH keys found with keyword '$KEYWORD' in user comment"
        exit 1
    fi
    
    # Extract complete SSH key lines (handle multi-line keys)
    # Use awk to handle multi-line keys properly
    awk -v keyword="$KEYWORD" '
    BEGIN { in_key = 0; key_line = "" }
    /^ssh-/ { 
        if (in_key && key_line ~ keyword) print key_line
        in_key = 1
        key_line = $0
    }
    in_key && !/^ssh-/ { 
        key_line = key_line $0
    }
    in_key && /^ssh-/ && $0 !~ keyword { 
        in_key = 0
    }
    END { 
        if (in_key && key_line ~ keyword) print key_line
    }
    ' "$AUTHORIZED_KEYS" > "$TEMP_KEYS"
    
    local count=$(wc -l < "$TEMP_KEYS")
    log "Found $count matching SSH key(s)"
    
    # Debug output
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Extracted keys:"
        cat "$TEMP_KEYS" | while read -r line; do
            log "DEBUG: Key line: $line"
        done
    fi
}

# Create URL-safe access token from fingerprint
create_url_safe_token() {
    local fingerprint="$1"
    
    # Remove colons and convert to lowercase for URL safety
    local token="${fingerprint//:/}"
    token="${token,,}"  # Convert to lowercase
    
    # Replace any remaining special characters that might cause URL issues
    # Keep only alphanumeric characters and common safe characters
    token=$(echo "$token" | sed 's/[^a-zA-Z0-9_-]//g')
    
    echo "$token"
}

# Calculate fingerprint and create access token
calculate_access_token() {
    local key_line="$1"
    local pub_key
    
    # Debug output
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Processing key line: $key_line"
    fi
    
    # Extract the public key portion (second field)
    pub_key=$(echo "$key_line" | awk '{print $2}')
    
    if [ -z "$pub_key" ]; then
        error "Could not extract public key from line: $key_line"
        return 1
    fi
    
    # Debug output
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Extracted public key: $pub_key"
    fi
    
    # Calculate fingerprint using ssh-keygen
    local fingerprint
    # Create a temporary file for the full key line
    local temp_key_file=$(mktemp)
    echo "$key_line" > "$temp_key_file"
    
    if ! fingerprint=$(ssh-keygen -lf "$temp_key_file" 2>/dev/null | awk '{print $2}'); then
        error "Failed to calculate fingerprint for key"
        if [ "${AHOST_DEBUG:-}" = "1" ]; then
            error "DEBUG: Attempted to calculate fingerprint for: $key_line"
        fi
        rm -f "$temp_key_file"
        return 1
    fi
    
    # Clean up temp file
    rm -f "$temp_key_file"
    
    # Debug output - show the fingerprint
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Calculated fingerprint: $fingerprint"
    fi
    
    # Create URL-safe access token
    local access_token
    access_token=$(create_url_safe_token "$fingerprint")
    
    # Debug output - show the access token creation
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Created access token from fingerprint: $access_token"
    fi
    
    log "Generated access token: ${access_token:0:16}..."
    echo "$access_token"
}

# Send access token to server and get script
request_script() {
    local access_token="$1"
    local response
    
    # Debug output - show the access token being used
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Using access token: $access_token"
    fi
    
    log "Sending access token to server: $SERVER_URL/$ENDPOINT_ENROLL"
    
    # Make curl request with timeout (no URL encoding needed for SHA256 fingerprints)
    # Debug output - show the token being sent
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Sending token: $access_token"
        log "DEBUG: Full request URL: $SERVER_URL/$ENDPOINT_ENROLL?access_token=$access_token"
    fi
    
    # Use POST request to avoid URL length limits
    if ! response=$(curl -s -L --max-time 30 --connect-timeout 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{\"access_token\":\"$access_token\"}" \
        "$SERVER_URL/$ENDPOINT_ENROLL" 2>/dev/null); then
        error "Failed to connect to server: $SERVER_URL/$ENDPOINT_ENROLL"
        return 1
    fi
    
    # Debug output
    if [ "${AHOST_DEBUG:-}" = "1" ]; then
        log "DEBUG: Server response: $response"
    fi
    
    # Check if response is empty
    if [ -z "$response" ]; then
        error "Empty response from server"
        return 1
    fi
    
    # Check for JSON error responses
    if echo "$response" | grep -q -E '^\s*\{.*"code"'; then
        error "Server returned JSON error: $response"
        return 1
    fi
    
    # Check for HTTP error status patterns
    if echo "$response" | grep -q -E "(error|Error|ERROR|not found|unauthorized|401|403|404|500)"; then
        error "Server returned error: $response"
        return 1
    fi
    
    # Check if response looks like a script (should start with #! or be bash content)
    #if ! echo "$response" | head -1 | grep -q -E "(#!/|#.*bash|echo|set)"; then
    #    error "Server response doesn't appear to be a valid script: $(echo "$response" | head -1)"
    #    return 1
    #fi
    
    echo "$response"
}

# Generate SSH key pair with special keyword comment
generate_ssh_key() {
    local key_type="${1:-ed25519}"
    local key_name="${2:-ahost-orchestra.key}"
    local key_path="$HOME/.ssh/${key_name}"
    local pub_key_path="${key_path}.pub"
    local authorized_keys_entry
    
    log "Generating SSH key pair: $key_name"
    
    # Check if key already exists
    if [ -f "$key_path" ]; then
        error "SSH key already exists: $key_path"
        error "Use --force to overwrite or choose a different name"
        return 1
    fi
    
    # Generate SSH key
    log "Creating SSH key with type: $key_type"
    if ! ssh-keygen -t "$key_type" -f "$key_path" -C "$KEYWORD" -N ""; then
        error "Failed to generate SSH key"
        return 1
    fi
    
    # Set proper permissions
    chmod 600 "$key_path"
    chmod 644 "$pub_key_path"
    
    # Create authorized_keys entry
    authorized_keys_entry="$(cat "$pub_key_path")"
    
    # Add to authorized_keys if it doesn't exist
    if [ -f "$AUTHORIZED_KEYS" ]; then
        if ! grep -q "$KEYWORD" "$AUTHORIZED_KEYS" 2>/dev/null; then
            log "Adding key to authorized_keys file"
            echo "$authorized_keys_entry" >> "$AUTHORIZED_KEYS"
            chmod 600 "$AUTHORIZED_KEYS"
        else
            warn "Key with keyword '$KEYWORD' already exists in authorized_keys"
        fi
    else
        log "Creating authorized_keys file"
        mkdir -p "$HOME/.ssh"
        echo "$authorized_keys_entry" > "$AUTHORIZED_KEYS"
        chmod 600 "$AUTHORIZED_KEYS"
    fi
    
    # Calculate fingerprint and access token
    local fingerprint
    fingerprint=$(ssh-keygen -lf "$pub_key_path" | awk '{print $2}')
    local access_token
    access_token=$(create_url_safe_token "$fingerprint")
    
    # Display results
    echo
    success "SSH key generated successfully!"
    echo
    echo "=== Key Information ==="
    echo "Private key: $key_path"
    echo "Public key:  $pub_key_path"
    echo "Fingerprint: $fingerprint"
    echo "Access token: $access_token"
    echo
    echo "=== Public Key (for server database) ==="
    echo "$authorized_keys_entry"
    echo
    echo "=== Next Steps ==="
    echo "1. Add this public key to your server's access_tokens table"
    echo "2. Update the token field with: $access_token"
    echo "3. Run the client script to test: $0"
    echo
    
    return 0
}

# Save and execute script
execute_script() {
    local script_content="$1"
    local script_path="$CLI_DIR/ahost-script-$(date +%Y%m%d-%H%M%S).sh"
    
    # Ensure CLI directory exists
    mkdir -p "$CLI_DIR"
    
    # Save script content
    echo "$script_content" > "$script_path"
    chmod +x "$script_path"
    
    log "Script saved to: $script_path"
    
    # Execute the script
    log "Executing script..."
    if bash "$script_path"; then
        success "Script executed successfully"
    else
        error "Script execution failed"
        return 1
    fi
}

# Main execution
main() {
    log "Starting AHost Orchestra Client"
    
    # Check dependencies
    for cmd in ssh-keygen curl awk grep; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check if SERVER_URL is configured
    if [ "$SERVER_URL" = "https://your-supabase-instance.supabase.co" ]; then
        warn "Using default server URL. Set AHOST_SERVER_URL environment variable to configure."
    fi
    
    # Execute main workflow
    check_authorized_keys
    find_matching_keys
    
    # Process each matching key
    local processed=0
    while IFS= read -r key_line; do
        log "Processing key: $(echo "$key_line" | awk '{print $1, $3}')"
        
        # Calculate access token
        local access_token
        if ! access_token=$(calculate_access_token "$key_line"); then
            warn "Skipping key due to fingerprint calculation error"
            continue
        fi
        
        # Debug output - show the calculated access token
        if [ "${AHOST_DEBUG:-}" = "1" ]; then
            log "DEBUG: Calculated access token: $access_token"
        fi
        
        # Request script from server
        local script_content
        if ! script_content=$(request_script "$access_token"); then
            warn "Skipping key due to server request error"
            continue
        fi
        
        # Execute script
        if execute_script "$script_content"; then
            success "Successfully processed key and executed script"
            processed=$((processed + 1))
        else
            warn "Script execution failed for this key"
        fi
        
    done < "$TEMP_KEYS"
    
    if [ $processed -eq 0 ]; then
        error "No keys were successfully processed"
        exit 1
    else
        success "Successfully processed $processed key(s)"
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        cat << EOF
AHost Orchestra Client

Usage: $0 [options] [command]

Commands:
  generate [key-type] [key-name]  Generate SSH key pair with special keyword
                                  key-type: rsa, ed25519, ecdsa (default: ed25519)
                                  key-name: name for the key file (default: ahost-orchestra)

Environment Variables:
  AHOST_SERVER_URL    Server URL for script requests
                      (default: https://your-supabase-instance.supabase.co)
  AHOST_KEYWORD       SSH key comment keyword (default: key@ahostorchestra)

Options:
  -h, --help          Show this help message

Examples:
  $0                           # Run orchestration (default behavior)
  $0 generate                  # Generate ed25519 key named 'ahost-orchestra'
  $0 generate rsa my-key       # Generate RSA key named 'my-key'

This script can either:
1. Search for SSH keys with "key@ahostorchestra" in the user comment,
   calculate their fingerprints, and use them as access tokens to request scripts
2. Generate new SSH key pairs with the special keyword in the comment

EOF
        exit 0
        ;;
    generate)
        # Generate SSH key
        key_type="${2:-ed25519}"
        key_name="${3:-ahost-orchestra}"
        
        # Validate key type
        case "$key_type" in
            rsa|ed25519|ecdsa)
                ;;
            *)
                error "Invalid key type: $key_type"
                error "Supported types: rsa, ed25519, ecdsa"
                exit 1
                ;;
        esac
        
        generate_ssh_key "$key_type" "$key_name"
        exit $?
        ;;
    "")
        # Default behavior - run orchestration
        main "$@"
        ;;
    *)
        error "Unknown command: $1"
        error "Use --help for usage information"
        exit 1
        ;;
esac