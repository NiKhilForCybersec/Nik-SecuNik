```bash
#!/bin/bash

set -e

echo "🚀 SecuNik LogX Setup Script"
echo "============================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check prerequisites
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 is not installed${NC}"
        return 1
    else
        echo -e "${GREEN}✓ $1 is installed${NC}"
        return 0
    fi
}

echo -e "\n${YELLOW}Checking prerequisites...${NC}"
MISSING_DEPS=0

check_command python3 || MISSING_DEPS=1
check_command pip3 || MISSING_DEPS=1
check_command node || MISSING_DEPS=1
check_command npm || MISSING_DEPS=1
check_command docker || MISSING_DEPS=1
check_command docker-compose || MISSING_DEPS=1

if [ $MISSING_DEPS -eq 1 ]; then
    echo -e "\n${RED}Please install missing dependencies before continuing.${NC}"
    exit 1
fi

# Create directory structure
echo -e "\n${YELLOW}Creating directory structure...${NC}"
mkdir -p storage/{uploads,parsed,analysis,temp}
mkdir -p rules/{yara,sigma,custom}
mkdir -p logs
mkdir -p tests/test_files

# Setup Python environment
echo -e "\n${YELLOW}Setting up Python environment...${NC}"
cd backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Setup Node environment
echo -e "\n${YELLOW}Setting up Node environment...${NC}"
cd ../frontend
npm install

# Create environment files
echo -e "\n${YELLOW}Creating environment files...${NC}"
cd ..
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}Please edit .env file with your API keys${NC}"
fi

if [ ! -f frontend/.env ]; then
    cp frontend/.env.example frontend/.env
fi

# Download initial rules
echo -e "\n${YELLOW}Downloading initial rules...${NC}"
python3 scripts/download_rules.py

# Initialize database
echo -e "\n${YELLOW}Initializing database...${NC}"
cd backend
source venv/bin/activate
python -c "from core.storage_manager import StorageManager; StorageManager().initialize_db()"

# Build Docker images
echo -e "\n${YELLOW}Building Docker images...${NC}"
cd ..
docker-compose -f docker-compose.dev.yml build

# Create test files
echo -e "\n${YELLOW}Creating test files...${NC}"
echo "Test log entry" > tests/test_files/test.log
echo '{"timestamp": "2024-01-01", "message": "test"}' > tests/test_files/test.json

echo -e "\n${GREEN}✓ Setup complete!${NC}"
echo -e "\nTo start the application:"
echo -e "  ${YELLOW}docker-compose -f docker-compose.dev.yml up${NC}"
echo -e "\nOr run services individually:"
echo -e "  Backend:  ${YELLOW}cd backend && source venv/bin/activate && uvicorn main:app --reload${NC}"
echo -e "  Frontend: ${YELLOW}cd frontend && npm run dev${NC}"
```

---