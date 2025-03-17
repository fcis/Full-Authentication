using AuthProject.Application.DTOs;
using AuthProject.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Application.Extensions
{
    public static class MappingExtensions
    {
        // User -> UserDto
        public static UserDto ToDto(this User user)
        {
            return new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                IsActive = user.IsActive,
                CreatedAt = user.CreatedAt,
                LastLogin = user.LastLogin
            };
        }

        // Collection mapping
        public static IEnumerable<UserDto> ToDtos(this IEnumerable<User> users)
        {
            return users.Select(u => u.ToDto());
        }

        // User + Tokens -> AuthResultDto
        public static AuthResultDto ToAuthResult(this User user, string token, string refreshToken, DateTime expiresAt)
        {
            return new AuthResultDto
            {
                Token = token,
                RefreshToken = refreshToken,
                ExpiresAt = expiresAt,
                Username = user.Username,
                Email = user.Email
            };
        }
    }
}
