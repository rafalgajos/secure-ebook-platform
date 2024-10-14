# Secure-Ebook-Platform

---

<div style="text-align: center;">
    <img src="images/hacker.jpg" alt="Secure Ebook Platform" width="50%">
</div>

---

## Project Description
Secure-Ebook-Platform is a web application developed using Flask, aimed at managing e-books with a strong focus on security. The platform implements protection against various web vulnerabilities, such as SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Session Hijacking, and File Upload attacks. It features a clean and user-friendly interface based on the "Ebook Landing" template and provides security mechanisms for a safe and secure user experience.

## Table of Contents
1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Project Schedule](#project-schedule)
5. [Contributors](#contributors)
6. [License](#license)

## Features <a name="features"></a>
- **E-book Management**: Securely add, view, and manage e-books on the platform.
- **SQL Injection Protection**: Parametrized queries to prevent malicious SQL injections.
- **Cross-Site Scripting (XSS) Prevention**: Input validation and output encoding to safeguard against XSS attacks.
- **Session Hijacking Protection**: Implement session validation techniques to ensure session security.
- **CSRF Protection**: Use CSRF tokens to prevent unauthorized requests.
- **Secure File Uploads**: Validate file types and content to protect against malicious uploads.
- **Security Testing Interface**: Easily enable and disable individual security features for testing purposes via the user interface.

## Installation <a name="installation"></a>
1. Clone the repository:  
   ```bash
   git clone https://github.com/rafalgajos/secure-ebook-platform.git
   ```
2. Navigate to the project directory:  
   ```bash
   cd secure-ebook-platform
   ```
3. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:  
   ```bash
   flask run
   ```

## Usage <a name="usage"></a>

- Start the application.
- Use the interface to upload and manage e-books.
- Test security features by enabling/disabling protection mechanisms from the navigation bar.
- Review e-books and submit reviews, protected against SQL Injection and XSS.

## Project Schedule <a name="project-schedule"></a>

- **Initial Planning**: Define project scope, analyze vulnerabilities (SQL Injection, XSS, CSRF, Session Hijacking, File Upload), and select tools and technologies.
- **Basic Application Structure**: Create views, routing, and session management. Implement basic session security.
- **SQL Injection Protection**: Add a review module secured against SQL Injection by parametrizing SQL queries.
- **XSS Protection — Milestone 1**: Implement XSS prevention mechanisms, input validation, and HTML escaping.
- **Session Hijacking Protection**: Enhance session security by checking IP and User-Agent for session validation.
- **CSRF Protection**: Implement CSRF tokens in forms to prevent unauthorized requests.
- **Secure File Uploads — Milestone 2**: Implement secure file uploads with MIME type validation and content checks.
- **Security Testing and Final Documentation**: Conduct security tests (SQL Injection, XSS, CSRF, Session Hijacking, File Upload) and finalize documentation.
- **Final Adjustments and Submission**: Complete any final fixes, perform testing, and prepare the project for submission.

## Contributors <a name="contributors"></a>

- Natalia Brzezińska
- Rafał Gajos

## License <a name="license"></a>

This project is protected under copyright law.  
Copyright 2024 Natalia Brzezińska, Rafał Gajos  
All Rights Reserved.
