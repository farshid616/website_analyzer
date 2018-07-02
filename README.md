# website_analyzer
This Project is a tornado webserver, receive an url, capture first page text and extract text sentiment

## Details
Simply enter an url on first page and receive most 100 frequest uesd word. You can see all of word and sentiment analysis on admin page. For sentiment analysis we used wit.ai api and receive positive negative and neutral for text values.

## Requarements:
* Python 3.6

Python Libraries:
* PyMySQL==0.8.0
* aiomysql
* bcrypt
* tornado
* wit
* pycrypto
* beautifulsoup4

## How to run
After installing docker and docker-compose
Just run docker-compose up in your project directory and check 0.0.0.0:8888 for result

## Author
Farshid Abdollahi

