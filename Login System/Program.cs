using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LoginSystem
{
    class Program
    {
        static readonly AuthService Auth = new(maxAttempts: 3, lockoutSeconds: 20);

        static void Main()
        {
            Console.Title = "Login System - Day 10";
            SeedUsers();

            while (true)
            {
                ShowMenu();
                switch ((Console.ReadLine() ?? "").Trim())
                {
                    case "1": Register(); break;
                    case "2": Login(); break;
                    case "3": ChangePassword(); break;
                    case "4": ListUsers(); break; // read-only peek
                    case "0": Info("Bye 👋"); return;
                    default: Warn("Invalid choice."); break;
                }
            }
        }

        static void ShowMenu()
        {
            Console.WriteLine();
            Console.WriteLine("=== Login System ===");
            Console.WriteLine("1) Register");
            Console.WriteLine("2) Login");
            Console.WriteLine("3) Change password");
            Console.WriteLine("4) List users (names only)");
            Console.WriteLine("0) Exit");
            Console.Write("Choose: ");
        }

        static void Register()
        {
            Console.Write("Username: ");
            var user = (Console.ReadLine() ?? "").Trim();
            if (string.IsNullOrWhiteSpace(user)) { Warn("Username required."); return; }

            Console.Write("Password: ");
            var pass = ReadHidden();

            try
            {
                Auth.Register(user, pass);
                Notify("✅ Registered successfully.");
            }
            catch (UserAlreadyExistsException ex)
            {
                Warn(ex.Message);
            }
            catch (Exception ex)
            {
                Error("Unexpected error during registration.", ex);
            }
        }

        static void Login()
        {
            Console.Write("Username: ");
            var user = (Console.ReadLine() ?? "").Trim();

            Console.Write("Password: ");
            var pass = ReadHidden();

            try
            {
                var profile = Auth.Login(user, pass);
                Notify($"✅ Welcome, {profile.Username}!");
            }
            catch (LockedOutException ex)
            {
                Warn($"⏳ Account locked. Try again in {ex.RemainingSeconds}s.");
            }
            catch (UserNotFoundException ex)
            {
                Warn(ex.Message);
            }
            catch (InvalidPasswordException ex)
            {
                Warn(ex.Message);
                Info($"Attempts left: {ex.AttemptsLeft}");
            }
            catch (Exception ex)
            {
                Error("Unexpected login error.", ex);
            }
            finally
            {
                // Could log audit info here
            }
        }

        static void ChangePassword()
        {
            Console.Write("Username: ");
            var user = (Console.ReadLine() ?? "").Trim();

            Console.Write("Old password: ");
            var oldPass = ReadHidden();

            Console.Write("New password: ");
            var newPass = ReadHidden();

            try
            {
                Auth.ChangePassword(user, oldPass, newPass);
                Notify("✅ Password changed.");
            }
            catch (LockedOutException ex)
            {
                Warn($"⏳ Account locked. Try again in {ex.RemainingSeconds}s.");
            }
            catch (UserNotFoundException ex)
            {
                Warn(ex.Message);
            }
            catch (InvalidPasswordException ex)
            {
                Warn(ex.Message);
                Info($"Attempts left: {ex.AttemptsLeft}");
            }
            catch (WeakPasswordException ex)
            {
                Warn($"Weak password: {ex.Message}");
            }
            catch (Exception ex)
            {
                Error("Unexpected error changing password.", ex);
            }
        }

        static void ListUsers()
        {
            var names = Auth.AllUsers().Select(u => u.Username).OrderBy(n => n).ToList();
            if (names.Count == 0) { Info("No users."); return; }

            Console.WriteLine("\nUsers:");
            foreach (var n in names) Console.WriteLine($"- {n}");
        }

        // --- Helpers ---
        static string ReadHidden()
        {
            var sb = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
                if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Length--; Console.Write("\b \b");
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    sb.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            return sb.ToString();
        }

        static void Warn(string msg) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine(msg); Console.ResetColor(); }
        static void Notify(string msg) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine(msg); Console.ResetColor(); }
        static void Info(string msg) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine(msg); Console.ResetColor(); }
        static void Error(string msg, Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"{msg}\n→ {ex.GetType().Name}: {ex.Message}");
            Console.ResetColor();
        }

        static void SeedUsers()
        {
            if (!Auth.Exists("admin")) Auth.Register("admin", "Admin@123"); // demo user
            if (!Auth.Exists("ali")) Auth.Register("ali", "Ali@12345");
        }
    }

    // ===== Domain =====
    class User
    {
        public string Username { get; init; } = "";
        public string PasswordHash { get; set; } = "";
        public int FailedAttempts { get; set; }
        public DateTime? LockedUntil { get; set; }
        public DateTime CreatedAt { get; init; } = DateTime.Now;
    }

    class AuthService
    {
        private readonly Dictionary<string, User> _users = new(StringComparer.OrdinalIgnoreCase);
        private readonly int _maxAttempts;
        private readonly int _lockoutSeconds;

        public AuthService(int maxAttempts, int lockoutSeconds)
        {
            _maxAttempts = maxAttempts;
            _lockoutSeconds = lockoutSeconds;
        }

        public bool Exists(string username) => _users.ContainsKey(username);

        public IEnumerable<User> AllUsers() => _users.Values;

        public void Register(string username, string password)
        {
            if (Exists(username)) throw new UserAlreadyExistsException(username);
            if (!IsStrong(password)) throw new WeakPasswordException("Min 8 chars, 1 upper, 1 lower, 1 digit.");

            _users[username] = new User
            {
                Username = username,
                PasswordHash = Hash(password)
            };
        }

        public User Login(string username, string password)
        {
            var user = FindUserOrThrow(username);
            EnsureNotLockedOrThrow(user);

            if (!Verify(password, user.PasswordHash))
            {
                user.FailedAttempts++;
                int remaining = Math.Max(0, _maxAttempts - user.FailedAttempts);

                if (user.FailedAttempts >= _maxAttempts)
                {
                    user.LockedUntil = DateTime.Now.AddSeconds(_lockoutSeconds);
                    user.FailedAttempts = 0; // reset after lock
                    int secs = RemainingSeconds(user);
                    throw new LockedOutException(secs <= 0 ? _lockoutSeconds : secs);
                }

                throw new InvalidPasswordException("❌ Invalid password.", remaining);
            }

            // success
            user.FailedAttempts = 0;
            user.LockedUntil = null;
            return user;
        }

        public void ChangePassword(string username, string oldPassword, string newPassword)
        {
            var user = Login(username, oldPassword); // will throw if wrong/locked
            if (!IsStrong(newPassword))
                throw new WeakPasswordException("Min 8 chars, 1 upper, 1 lower, 1 digit.");

            user.PasswordHash = Hash(newPassword);
        }

        // --- internals ---
        private User FindUserOrThrow(string username)
        {
            if (!_users.TryGetValue(username, out var u))
                throw new UserNotFoundException(username);
            return u;
        }

        private void EnsureNotLockedOrThrow(User u)
        {
            if (u.LockedUntil is null) return;
            var remaining = RemainingSeconds(u);
            if (remaining > 0) throw new LockedOutException(remaining);
            u.LockedUntil = null;
            u.FailedAttempts = 0;
        }

        private static bool IsStrong(string p)
        {
            if (string.IsNullOrEmpty(p) || p.Length < 8) return false;
            bool hasUpper = p.Any(char.IsUpper);
            bool hasLower = p.Any(char.IsLower);
            bool hasDigit = p.Any(char.IsDigit);
            return hasUpper && hasLower && hasDigit;
        }

        private static string Hash(string s)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(bytes); // .NET 5+
        }

        private static bool Verify(string plain, string hash) => Hash(plain).Equals(hash, StringComparison.OrdinalIgnoreCase);

        private static int RemainingSeconds(User u)
        {
            if (u.LockedUntil is null) return 0;
            var diff = (int)Math.Ceiling((u.LockedUntil.Value - DateTime.Now).TotalSeconds);
            return Math.Max(0, diff);
        }
    }

    // ===== Exceptions =====
    class UserAlreadyExistsException : Exception
    {
        public UserAlreadyExistsException(string username)
            : base($"User '{username}' already exists.") { }
    }

    class UserNotFoundException : Exception
    {
        public UserNotFoundException(string username)
            : base($"User '{username}' not found.") { }
    }

    class InvalidPasswordException : Exception
    {
        public int AttemptsLeft { get; }
        public InvalidPasswordException(string message, int attemptsLeft) : base(message)
            => AttemptsLeft = attemptsLeft;
    }

    class LockedOutException : Exception
    {
        public int RemainingSeconds { get; }
        public LockedOutException(int remainingSeconds)
            : base("Account locked due to too many failed attempts.")
            => RemainingSeconds = remainingSeconds;
    }

    class WeakPasswordException : Exception
    {
        public WeakPasswordException(string message) : base(message) { }
    }
}
