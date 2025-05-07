FROM python:3.11-slim as base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    gcc \
    libpq-dev \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools (extract only the binary)
RUN curl -L https://github.com/projectdiscovery/subfinder/releases/download/v2.7.1/subfinder_2.7.1_linux_amd64.zip -o subfinder.zip \
    && unzip -j subfinder.zip 'subfinder' -d /usr/local/bin/ \
    && rm subfinder.zip
RUN curl -L https://github.com/projectdiscovery/katana/releases/download/v1.1.3/katana_1.1.3_linux_amd64.zip -o katana.zip \
    && unzip -j katana.zip 'katana' -d /usr/local/bin/ \
    && rm katana.zip
RUN curl -L https://github.com/projectdiscovery/naabu/releases/download/v2.3.4/naabu_2.3.4_linux_amd64.zip -o naabu.zip \
    && unzip -j naabu.zip 'naabu' -d /usr/local/bin/ \
    && rm naabu.zip
RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.4.2/nuclei_3.4.2_linux_amd64.zip -o nuclei.zip \
    && unzip -j nuclei.zip 'nuclei' -d /usr/local/bin/ \
    && rm nuclei.zip

# Copy requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

ENV PATH="/usr/local/bin:$PATH"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"] 