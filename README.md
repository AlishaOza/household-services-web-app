# Household Services App

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction
The Household Services App is designed to connect customers with professional service providers. Users can create service requests, and professionals can manage and respond to these requests. This app aims to streamline the process of finding and offering household services.

## Features
- User registration and role selection (Customer/Professional)
- Dashboard for customers to create service requests
- Dashboard for professionals to manage requests
- Search functionality for Admin to find Customers and Professionals
- Responsive design for mobile and desktop

## Technologies Used
- **Backend:** Flask, SQLAlchemy
- **Frontend:** HTML, CSS, Bootstrap
- **Database:** SQLite
- **Libraries:** Flask-WTF for form handling, Jinja2 for templating

## Installation
1. Clone the repository:
   - git clone https://github.com/yourusername/household_services_app.git
   - cd household_services_app
2. Create a virtual environment:
   - python -m venv venv
   - source venv/bin/activate (On Windows use `venv\Scripts\activate`)
4. Install the required packages:
   - pip install -r requirements.txt
5. Run the application
   - flask run
