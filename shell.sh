python -m venv venv

source venv/bin/activate

pip freeze > requirements.txt

pip download -r requirements.txt -d packages/

pip install  --no-index --find-links=packages/ -r requirements.txt

tar -czf scan_ip.tar.gz scan_ip/ 

tar -xzf scan_ip.tar.gz