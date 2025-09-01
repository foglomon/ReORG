import ollama
import os


with open('sample.txt', 'r', encoding='utf-8') as file:
    file_content = file.read()

response = ollama.chat(
    model='llava',
    messages=[{'role':'user', 'content': f'Analyze this file content and suggest a folder structure:\n\n{file_content}'}],)

print(response['message']['content'])

#run ollama pull llava