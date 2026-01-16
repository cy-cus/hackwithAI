# Ultimate Bug Bounty Platform - Docker Container
# All tools pre-installed, no local setup needed

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    build-essential \
    python3 \
    python3-pip \
    python3-dev \
    chromium-browser \
    chromium-chromedriver \
    ca-certificates \
    libssl-dev \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for ProjectDiscovery tools and Amass)
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
RUN nuclei -update-templates

# Install waybackurls
RUN go install github.com/tomnomnom/waybackurls@latest

# Set working directory
WORKDIR /app

# Copy application code
COPY requirements.txt .
COPY reconai/ ./reconai/
COPY README.md .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install chromium && \
    playwright install-deps chromium

# Create output directory
RUN mkdir -p /app/output

# Expose port
EXPOSE 1337

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:1337/api/health || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Run the application
CMD ["python3", "-m", "reconai.web.app"]
