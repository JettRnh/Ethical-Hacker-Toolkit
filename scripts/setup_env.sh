#!/bin/bash
# Environment setup script for Ethical Hacker Toolkit
# Author: Jet

echo "Ethical Hacker Toolkit - Environment Setup"
echo "=========================================="
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

# Create virtual environment
echo ""
echo "[2/5] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo ""
echo "[3/5] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "[4/5] Installing dependencies..."
pip install -r requirements.txt

# Install package in development mode
echo ""
echo "[5/5] Installing toolkit..."
pip install -e .

# Create default wordlists if not exist
echo ""
echo "Creating default wordlists..."
mkdir -p config/wordlists

if [ ! -f config/wordlists/directories.txt ]; then
    cat > config/wordlists/directories.txt << 'EOF'
admin
backup
config
css
data
docs
download
images
img
includes
js
logs
private
public
static
system
temp
test
tmp
upload
user
wp-admin
wp-content
wp-includes
api
v1
v2
assets
media
files
uploads
downloads
cgi-bin
phpmyadmin
mysql
sql
database
db
back
old
new
dev
staging
stage
prod
production
test
testing
demo
example
sample
src
source
lib
vendor
node_modules
packages
bin
sbin
usr
etc
var
opt
home
root
EOF
fi

if [ ! -f config/wordlists/subdomains.txt ]; then
    cat > config/wordlists/subdomains.txt << 'EOF'
www
mail
ftp
localhost
webmail
smtp
pop
pop3
imap
dns
ns1
ns2
ns3
ns4
api
app
apps
blog
blogs
cms
forum
forums
news
shop
store
secure
portal
admin
manage
manager
dashboard
control
panel
cp
cpanel
whm
webdisk
webdav
mysql
pgsql
sql
db
database
backup
backups
dev
development
test
testing
stage
staging
beta
alpha
demo
example
sample
sandbox
playground
docs
documentation
help
support
faq
kb
knowledgebase
wiki
git
svn
repo
repository
jenkins
ci
cd
build
deploy
artifacts
monitor
monitoring
status
stats
statistics
analytics
metrics
logs
log
trace
debug
error
profile
config
configuration
settings
setup
install
installer
update
updates
upgrade
upgrades
patch
patches
release
releases
download
downloads
media
assets
static
cdn
cache
proxy
lb
loadbalancer
gateway
api-gateway
auth
oauth
login
signin
signup
register
registration
account
accounts
user
users
member
members
profile
profiles
dashboard
console
shell
terminal
ssh
sftp
scp
rdp
vnc
remote
remoteaccess
vpn
openvpn
wireguard
ipsec
ssl
tls
cert
certs
ca
pki
crypto
encrypt
decrypt
hash
EOF
fi

if [ ! -f config/wordlists/common_passwords.txt ]; then
    cat > config/wordlists/common_passwords.txt << 'EOF'
123456
password
123456789
12345
12345678
admin
qwerty
abc123
password1
admin123
letmein
welcome
monkey
dragon
master
sunshine
princess
baseball
football
superman
trustno1
iloveyou
starwars
whatever
nicole
jordan
harley
mustang
michael
shadow
ashley
bailey
ginger
pepper
buster
tiger
jasmine
killer
freedom
computer
internet
network
security
hacker
hackme
adminadmin
root
toor
oracle
postgres
mysql
test
test123
demo
demo123
sample
sample123
guest
guest123
user
user123
webmaster
administrator
sysadmin
support
info
office
school
college
university
student
teacher
professor
doctor
nurse
lawyer
engineer
developer
programmer
analyst
manager
director
ceo
cto
cfo
coo
president
vicepresident
chairman
board
member
staff
employee
corporate
company
business
enterprise
organization
institute
foundation
agency
department
division
section
unit
group
team
crew
staff
work
job
career
position
role
function
task
project
program
system
application
software
hardware
network
database
server
client
host
node
device
platform
framework
library
package
module
component
service
api
endpoint
interface
protocol
standard
format
type
class
object
instance
variable
function
method
property
attribute
value
data
info
information
content
record
file
document
folder
directory
path
link
url
uri
domain
hostname
ipaddress
address
port
socket
connection
session
token
key
certificate
credential
password
passphrase
secret
private
public
shared
common
default
standard
basic
advanced
expert
custom
userdefined
EOF
fi

echo ""
echo "Setup completed successfully!"
echo ""
echo "To activate the toolkit:"
echo "  source venv/bin/activate"
echo "  eht --help"
echo ""
echo "To run a quick scan:"
echo "  eht scan 127.0.0.1 -p 1-100"
echo "  eht whois google.com"
echo "  eht dns example.com"
