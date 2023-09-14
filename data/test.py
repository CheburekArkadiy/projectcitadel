from requests import get

print(get('http://127.0.0.1:8082/api/courses/4').json())

print(get('http://127.0.0.1:8082/api/courses/999').json())

