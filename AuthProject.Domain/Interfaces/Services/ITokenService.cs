using AuthProject.Domain.Common;
using AuthProject.Domain.Entities;
using AuthProject.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Services
{
    public interface ITokenService
    {
        string GenerateJwtToken(User user);
        string GenerateRefreshToken();
        string GenerateEmailConfirmationToken();
        string GeneratePasswordResetToken();
        DateTime GetJwtTokenExpiryDate();
        Task<Result<User>> ValidateTokenAsync(string token, TokenType tokenType);
    }
}
