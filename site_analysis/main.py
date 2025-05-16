from netrc import netrc

import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

app = Flask(__name__, static_folder='static')

COMMON_DIRECTORIES = [
    'admin', 'backup', 'config', 'database', 'doc', 'docs',
    'download', 'downloads', 'install', 'log', 'logs',
    'manager', 'old', 'phpmyadmin', 'server', 'sql',
    'tmp', 'upload', 'uploads', 'wp-admin', 'wp-content',
    'wp-includes', 'include', 'includes', 'assets', 'images',
    'img', 'js', 'css', 'static', 'public', 'private'
]

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Feature-Policy',
    'Permissions-Policy'
]


def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def check_site_exists(url):
    try:
        try:
            response = requests.head(
                url,
                timeout=5,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            if response.status_code < 400:
                return True
        except requests.exceptions.RequestException:
            pass

        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            return response.status_code < 400
        except requests.exceptions.RequestException:
            return False

    except Exception:
        return False


def check_https(url):
    try:
        https_url = url.replace('http://', 'https://')
        response = requests.get(https_url, timeout=5, allow_redirects=True)
        return True if response.url.startswith('https://') else False
    except:
        return False


def check_open_directories(base_url):
    open_dirs = []
    for directory in COMMON_DIRECTORIES:
        test_url = f"{base_url.rstrip('/')}/{directory}"
        try:
            response = requests.get(test_url, timeout=3)
            if response.status_code == 200 and 'index' in response.text.lower():
                open_dirs.append(directory)
        except:
            continue
    return open_dirs


def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        missing_headers = []
        present_headers = {}

        for header in SECURITY_HEADERS:
            if header not in headers:
                missing_headers.append(header)
            else:
                present_headers[header] = headers[header]

        return {
            'missing': missing_headers,
            'present': present_headers
        }
    except:
        return {'missing': SECURITY_HEADERS, 'present': {}}


def assess_danger_level(https_result, open_dirs, headers_result):
    score = 100

    penalties = []

    if not https_result:
        score -= 30
        penalties.append("Отсутствует HTTPS (-30)")

    open_dirs_penalty = min(len(open_dirs) * 5, 30)
    if open_dirs_penalty > 0:
        score -= open_dirs_penalty
        penalties.append(f"{len(open_dirs)} открытых директорий (-{open_dirs_penalty})")

    missing_headers_penalty = min(len(headers_result['missing']) * 5, 40)
    if missing_headers_penalty > 0:
        score -= missing_headers_penalty
        penalties.append(f"Отсутствуют {len(headers_result['missing'])} security headers (-{missing_headers_penalty})")

    score = max(0, score)

    if score >= 80:
        level = "Низкий"
        color = "green"
    elif score >= 50:
        level = "Средний"
        color = "orange"
    else:
        level = "Высокий"
        color = "red"

    explanation = f"Начальный балл: 100\n"
    if penalties:
        explanation += "Вычеты:\n- " + "\n- ".join(penalties)
    else:
        explanation += "Вычетов нет"

    explanation += f"\nИтоговый балл: {score}/100"

    return {
        'level': level,
        'score': score,
        'color': color,
        'explanation': explanation
    }

@app.route('/', methods=['GET', 'POST'])
def analysis():
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            return render_template('analysis.html', error="Пожалуйста, введите URL")

        try:
            normalized_url = normalize_url(url)
            domain = urlparse(normalized_url).netloc

            if not check_site_exists(normalized_url):
                return render_template('analysis.html', error="Сайт не существует или недоступен")

            https_result = check_https(normalized_url)

            open_dirs = check_open_directories(normalized_url)

            headers_result = check_security_headers(normalized_url)

            danger_result = assess_danger_level(
                https_result, open_dirs, headers_result
            )

            return render_template('analysis_results.html',
                                   url=normalized_url,
                                   domain=domain,
                                   https_result=https_result,
                                   open_dirs=open_dirs,
                                   headers_result=headers_result,
                                   danger_result=danger_result,
                                   )

        except Exception as e:
            return render_template('analysis.html', error=f"Ошибка при анализе сайта: {str(e)}")

    return render_template('analysis.html')

if __name__ == '__main__':
    app.run(debug=True)
