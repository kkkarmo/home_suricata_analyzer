# Suricata Log Analyzer

## Overview

This project is a Suricata log analyzer that processes Suricata's EVE JSON logs, performs analysis on the events, and stores the results in both a PostgreSQL database and text files. It uses the Groq API for advanced analysis of network security events.

## Features

- Processes Suricata EVE JSON logs in real-time
- Filters events based on public IP addresses and a custom IP blacklist
- Performs detailed analysis of security events using the Groq API
- Stores analysis results in a PostgreSQL database
- Outputs analysis results to text files
- Runs in a Docker container for easy deployment and scalability

## Prerequisites

- Docker
- Docker Compose
- Suricata installed and generating EVE JSON logs
- Groq API key

## Installation

1. Clone the repository:

git clone https://github.com/kkkarmo/home_suricata_analyzer.git
cd home_suricata_analyzer
text

2. Create a `.env` file in the project root and add your Groq API key:

GROQ_API_KEY=your_groq_api_key_here
text

3. Update the `ip_blacklist.txt` file with any IP addresses you want to exclude from analysis.

4. Build and start the Docker containers:

docker-compose up --build -d
text

## Usage

The analyzer will automatically start processing Suricata logs once the Docker containers are up and running. You can monitor the output in several ways:

1. Check the Docker logs:

docker-compose logs -f suricata_analyzer
text

2. Examine the output text files in the `output` directory.

3. Query the PostgreSQL database for analysis results:

docker-compose exec db psql -U ids_user -d ids_db -c "SELECT * FROM suricata_events ORDER BY timestamp DESC LIMIT 5;"
text

## Configuration

You can modify the following files to customize the analyzer's behavior:

- `docker-compose.yml`: Update environment variables and volume mappings.
- `suricata_analyzer.py`: Modify the analysis logic or output format.
- `ip_blacklist.txt`: Add or remove IP addresses to be excluded from analysis.

## Troubleshooting

If you encounter any issues:

1. Check the Docker logs for error messages:

docker-compose logs suricata_analyzer
text

2. Verify that Suricata is generating logs in the expected location.

3. Ensure that the Groq API key is correctly set in the `.env` file.

4. Check the PostgreSQL database connection:

docker-compose exec suricata_analyzer python -c "import psycopg2; conn = psycopg2.connect(host='db', dbname='ids_db', user='ids_user', password='your_secure_password'); print('Database connection successful')"
text

## Contributing

Contributions to this project are welcome! Please fork the repository and submit a pull request with your changes.

## License

[Specify your license here, e.g., MIT, GPL, etc.]

## Contact

[Your Name or GitHub username]
[Your email or other contact information]

## Acknowledgements

- Suricata: https://suricata.io/
- Groq: https://groq.com/
- PostgreSQL: https://www.postgresql.org/
