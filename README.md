# 🔐 Login System CLI (C# Console App)

This is **Day 10** of my 30-Day C# Project-Based Learning Plan.  
A simple **login system** that demonstrates **exception handling, password hashing, retry limits, and lockouts**.  

---

## 🚀 Features
- Register new users with password rules  
- Login with retry limit and **temporary lockout**  
- Change password (old password required)  
- Passwords stored as **SHA256 hashes** (not plain text)  
- Exceptions for invalid users, wrong passwords, weak passwords, and lockouts  
- Console UX: hidden password input, colored output  

---

## 🛠️ Technologies
- Language: **C#**  
- Framework: **.NET 6/7/8**  
- IDE: Visual Studio  

---

## 📸 Screenshots

| 🔐 |
|-----|
| ![Screenshot](./Login.png)|

----

## 📚 Learning Goals

This project introduces:

- Custom exceptions (UserNotFoundException, InvalidPasswordException, etc.)

- try / catch / finally usage

- Password hashing with SHA256

- Lockout mechanism after too many failed attempts

- Hidden password input (Console.ReadKey(intercept: true))
