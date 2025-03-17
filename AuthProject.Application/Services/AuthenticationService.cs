using AuthProject.Application.DTOs;
using AuthProject.Application.Validators;
using AuthProject.Domain.Common;
using AuthProject.Domain.Entities;
using AuthProject.Domain.Enums;
using AuthProject.Domain.Interfaces.Services;
using AuthProject.Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AuthProject.Application.Extensions;

namespace AuthProject.Application.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService;
        private readonly IPasswordService _passwordService;
        private readonly RegisterDtoValidator _registerValidator;
        private readonly LoginDtoValidator _loginValidator;
        private readonly int _maxLoginAttempts = 3;
        private readonly TimeSpan _lockoutDuration = TimeSpan.FromHours(24);

        public AuthenticationService(
            IUnitOfWork unitOfWork,
            ITokenService tokenService,
            IEmailService emailService,
            IPasswordService passwordService,
            RegisterDtoValidator registerValidator,
            LoginDtoValidator loginValidator)
        {
            _unitOfWork = unitOfWork;
            _tokenService = tokenService;
            _emailService = emailService;
            _passwordService = passwordService;
            _registerValidator = registerValidator;
            _loginValidator = loginValidator;
        }

        public async Task<Result<AuthResultDto>> RegisterAsync(RegisterDto model)
        {
            // Validate the model
            var validationResult = await _registerValidator.ValidateAsync(model);
            if (!validationResult.IsValid)
            {
                return Result.Failure<AuthResultDto>(string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage)));
            }

            // Check if email already exists
            if (await _unitOfWork.Users.EmailExistsAsync(model.Email))
            {
                return Result.Failure<AuthResultDto>("Email is already registered");
            }

            // Check if username already exists
            if (await _unitOfWork.Users.UsernameExistsAsync(model.Username))
            {
                return Result.Failure<AuthResultDto>("Username is already taken");
            }

            // Hash password
            string passwordHash = _passwordService.HashPassword(model.Password);

            // Create user
            var user = new User
            {
                Username = model.Username,
                Email = model.Email,
                PasswordHash = passwordHash,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Add user to database
                await _unitOfWork.Users.AddAsync(user);
                await _unitOfWork.SaveChangesAsync();

                // Generate email confirmation token
                string token = _tokenService.GenerateEmailConfirmationToken();

                // Create user token
                var userToken = new UserToken
                {
                    UserId = user.Id,
                    TokenType = TokenType.EmailConfirmation,
                    Token = token,
                    ExpiryDate = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow
                };

                // Add user token to database
                await _unitOfWork.UserTokens.AddAsync(userToken);
                await _unitOfWork.SaveChangesAsync();

                // Send confirmation email
                await _emailService.SendEmailConfirmationAsync(user.Email, user.Username, token);

                // Generate JWT token
                string jwtToken = _tokenService.GenerateJwtToken(user);

                // Generate refresh token
                string refreshToken = _tokenService.GenerateRefreshToken();

                // Create refresh token entity
                var refreshTokenEntity = new RefreshToken
                {
                    UserId = user.Id,
                    Token = refreshToken,
                    ExpiryDate = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow,
                    CreatedByIp = "0.0.0.0" // Ideally, this would be the actual IP
                };

                // Add refresh token to database
                await _unitOfWork.RefreshTokens.AddAsync(refreshTokenEntity);
                await _unitOfWork.SaveChangesAsync();

                await _unitOfWork.CommitAsync();

                // Create auth response
                var expiresAt = _tokenService.GetJwtTokenExpiryDate();
                var response = user.ToAuthResult(jwtToken, refreshToken, expiresAt);

                return Result.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackAsync();
                return Result.Failure<AuthResultDto>($"Registration failed: {ex.Message}");
            }
        }

        public async Task<Result<AuthResultDto>> LoginAsync(LoginDto model)
        {
            // Validate the model
            var validationResult = await _loginValidator.ValidateAsync(model);
            if (!validationResult.IsValid)
            {
                return Result.Failure<AuthResultDto>(string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage)));
            }

            // Find user by email or username
            User user = null;

            // Check if input is email or username
            bool isEmail = model.UsernameOrEmail.Contains('@');

            if (isEmail)
            {
                user = await _unitOfWork.Users.GetByEmailAsync(model.UsernameOrEmail);
            }
            else
            {
                user = await _unitOfWork.Users.GetByUsernameAsync(model.UsernameOrEmail);
            }

            if (user == null)
            {
                return Result.Failure<AuthResultDto>("Invalid credentials");
            }

            // Check if user is active
            if (!user.IsActive)
            {
                return Result.Failure<AuthResultDto>("Account is disabled");
            }

            // Check if user is locked out
            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            {
                return Result.Failure<AuthResultDto>($"Account is locked out until {user.LockoutEnd}");
            }

            // Verify password
            bool validPassword = _passwordService.VerifyPassword(model.Password, user.PasswordHash);

            if (!validPassword)
            {
                // Increment login attempts
                user.LoginAttempts += 1;

                // Check if max login attempts reached
                if (user.LoginAttempts >= _maxLoginAttempts)
                {
                    user.LockoutEnd = DateTime.UtcNow.Add(_lockoutDuration);
                    user.LoginAttempts = 0;
                }

                await _unitOfWork.SaveChangesAsync();

                // If this was the attempt that locked them out, return locked out message
                if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
                {
                    return Result.Failure<AuthResultDto>($"Too many failed login attempts. Account is locked out until {user.LockoutEnd}");
                }

                return Result.Failure<AuthResultDto>("Invalid credentials");
            }

            // Reset login attempts
            user.LoginAttempts = 0;
            user.LastLogin = DateTime.UtcNow;

            await _unitOfWork.BeginTransactionAsync();

            try
            {
                await _unitOfWork.SaveChangesAsync();

                // Generate JWT token
                string token = _tokenService.GenerateJwtToken(user);

                // Generate refresh token
                string refreshToken = _tokenService.GenerateRefreshToken();

                // Create refresh token entity
                var refreshTokenEntity = new RefreshToken
                {
                    UserId = user.Id,
                    Token = refreshToken,
                    ExpiryDate = model.RememberMe ? DateTime.UtcNow.AddDays(30) : DateTime.UtcNow.AddDays(1),
                    CreatedAt = DateTime.UtcNow,
                    CreatedByIp = "0.0.0.0" // Ideally, this would be the actual IP
                };

                // Add refresh token to database
                await _unitOfWork.RefreshTokens.AddAsync(refreshTokenEntity);
                await _unitOfWork.SaveChangesAsync();

                await _unitOfWork.CommitAsync();

                // Create auth response
                var expiresAt = _tokenService.GetJwtTokenExpiryDate();
                var response = user.ToAuthResult(token, refreshToken, expiresAt);

                return Result.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackAsync();
                return Result.Failure<AuthResultDto>($"Login failed: {ex.Message}");
            }
        }

        public async Task<Result> ConfirmEmailAsync(ConfirmEmailDto model)
        {
            // Find user by email
            var user = await _unitOfWork.Users.GetByEmailAsync(model.Email);
            if (user == null)
            {
                return Result.Failure("Invalid token or email");
            }

            // Check if email is already confirmed
            if (user.EmailConfirmed)
            {
                return Result.Failure("Email is already confirmed");
            }

            // Find token
            var token = await _unitOfWork.UserTokens.GetByTokenAsync(model.Token, TokenType.EmailConfirmation);
            if (token == null || token.UserId != user.Id || token.IsUsed || token.ExpiryDate < DateTime.UtcNow)
            {
                return Result.Failure("Invalid token or email");
            }

            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Mark token as used
                token.IsUsed = true;

                // Confirm email
                user.EmailConfirmed = true;

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitAsync();

                return Result.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackAsync();
                return Result.Failure($"Email confirmation failed: {ex.Message}");
            }
        }

        public async Task<Result<AuthResultDto>> RefreshTokenAsync(RefreshTokenDto model, string ipAddress)
        {
            // Find refresh token
            var refreshToken = await _unitOfWork.RefreshTokens.GetByTokenAsync(model.RefreshToken);
            if (refreshToken == null || refreshToken.IsRevoked || refreshToken.ExpiryDate < DateTime.UtcNow)
            {
                return Result.Failure<AuthResultDto>("Invalid refresh token");
            }

            // Find user
            var user = await _unitOfWork.Users.GetByIdAsync(refreshToken.UserId);
            if (user == null || !user.IsActive)
            {
                return Result.Failure<AuthResultDto>("User not found or inactive");
            }

            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Revoke current refresh token
                refreshToken.IsRevoked = true;
                refreshToken.RevokedByIp = ipAddress;

                // Generate new JWT token
                string token = _tokenService.GenerateJwtToken(user);

                // Generate new refresh token
                string newRefreshToken = _tokenService.GenerateRefreshToken();

                // Create new refresh token entity
                var newRefreshTokenEntity = new RefreshToken
                {
                    UserId = user.Id,
                    Token = newRefreshToken,
                    ExpiryDate = DateTime.UtcNow.AddDays(7),
                    CreatedAt = DateTime.UtcNow,
                    CreatedByIp = ipAddress
                };

                // Add new refresh token to database
                await _unitOfWork.RefreshTokens.AddAsync(newRefreshTokenEntity);
                await _unitOfWork.SaveChangesAsync();

                await _unitOfWork.CommitAsync();

                // Create auth response
                var expiresAt = _tokenService.GetJwtTokenExpiryDate();
                var response = user.ToAuthResult(token, newRefreshToken, expiresAt);

                return Result.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackAsync();
                return Result.Failure<AuthResultDto>($"Token refresh failed: {ex.Message}");
            }
        }

        public async Task<Result> RevokeTokenAsync(string token, string ipAddress)
        {
            // Find refresh token
            var refreshToken = await _unitOfWork.RefreshTokens.GetByTokenAsync(token);
            if (refreshToken == null)
            {
                return Result.Failure("Token not found");
            }

            if (refreshToken.IsRevoked)
            {
                return Result.Failure("Token is already revoked");
            }

            // Revoke token
            refreshToken.IsRevoked = true;
            refreshToken.RevokedByIp = ipAddress;

            await _unitOfWork.SaveChangesAsync();

            return Result.Success();
        }
    }
}

