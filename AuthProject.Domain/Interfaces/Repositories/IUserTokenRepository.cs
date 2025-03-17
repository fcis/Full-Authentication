using AuthProject.Domain.Entities;
using AuthProject.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Repositories
{
    public interface IUserTokenRepository : IRepository<UserToken>
    {
        // Synchronous operations
        UserToken GetByToken(string token, TokenType tokenType);
        IEnumerable<UserToken> GetByUserId(Guid userId, TokenType tokenType);

        // Asynchronous operations
        Task<UserToken> GetByTokenAsync(string token, TokenType tokenType);
        Task<IEnumerable<UserToken>> GetByUserIdAsync(Guid userId, TokenType tokenType);
    }
}
