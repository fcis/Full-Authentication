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
using BC = BCrypt.Net.BCrypt;


namespace AuthProject.Application.Services
{
    public class PasswordService : IPasswordService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService;
        private readonly ForgotPasswordDtoValidator _forgotPasswordValidator;
        private readonly ResetPasswordDtoValidator _resetPasswordValidator;

        public PasswordService(
            IUnitOfWork unitOfWork,
            ITokenService tokenService,
            IEmailService emailService,
            ForgotPasswordDtoValidator forgotPasswordValidator,
            ResetPasswordDtoValidator resetPasswordValidator)
        {
            _unitOfWork = unitOfWork;
            _tokenService = tokenService;
            _emailService = emailService;
            _forgotPasswordValidator = forgotPasswordValidator;
            _resetPasswordValidator = resetPasswordValidator;
        }

        public async Task<Result> ForgotPasswordAsync<ForgotPasswordDto>(ForgotPasswordDto model)
        {

            // Validate the model
            var validationResult = await _forgotPasswordValidator.ValidateAsync(model);
            if (!validationResult.IsValid)
            {
                return Result.Failure(string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage)));
            }

            // Find user by email
            var user = await _unitOfWork.Users.GetByEmailAsync(model.Email);
            if (user == null)
            {
                // For security reasons, don't reveal that the email doesn't exist
                return Result.Success();
            }

            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Generate password reset token
                string token = _tokenService.GeneratePasswordResetToken();

                // Create user token
                var userToken = new UserToken
                {
                    UserId = user.Id,
                    TokenType = TokenType.PasswordReset,
                    Token = token,
                    ExpiryDate = DateTime.UtcNow.AddHours(24),
                    CreatedAt = DateTime.UtcNow
                };

                // Add user token to database
                await _unitOfWork.UserTokens.AddAsync(userToken);
                await _unitOfWork.SaveChangesAsync();

                // Send password reset email
                await _emailService.SendPasswordResetAsync(user.Email, user.Username, token);

                await _unitOfWork.CommitAsync();

                return Result.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackAsync();
                return Result.Failure($"Forgot password process failed: {ex.Message}");
            }
        }

        public async Task<Result> ResetPasswordAsync<ResetPasswordDto>(ResetPasswordDto model)
        {
            // Validate the model
            var validationResult = await _resetPasswordValidator.ValidateAsync(model);
            if (!validationResult.IsValid)
            {
                return Result.Failure(string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage)));
            }

            // Find user by email
            var user = await _unitOfWork.Users.GetByEmailAsync(model.Email);
            if (user == null)
            {
                return Result.Failure("Invalid token or email");
            }

            // Find token
            var token = await _unitOfWork.UserTokens.GetByTokenAsync(model.Token, TokenType.PasswordReset);
            if (token == null || token.UserId != user.Id || token.IsUsed || token.ExpiryDate < DateTime.UtcNow)
            {
                return Result.Failure("Invalid token or email");
            }

            await _unitOfWork.BeginTransactionAsync();

            try
            {
                // Mark token as used
                token.IsUsed = true;

                // Hash new password
                string passwordHash = HashPassword(model.NewPassword);

                // Update password
                user.PasswordHash = passwordHash;

                // Reset login attempts
                user.LoginAttempts = 0;
                user.LockoutEnd = null;

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitAsync();

                return Result.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackAsync();
                return Result.Failure($"Password reset failed: {ex.Message}");
            }
        }

        public string HashPassword(string password)
        {
            return BC.HashPassword(password);
        }

        public bool VerifyPassword(string password, string passwordHash)
        {
            return BC.Verify(password, passwordHash);
        }
    }
}
