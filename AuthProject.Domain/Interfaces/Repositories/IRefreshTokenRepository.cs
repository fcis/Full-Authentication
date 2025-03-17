using AuthProject.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Repositories
{
    public interface IRefreshTokenRepository : IRepository<RefreshToken>
    {
        // Synchronous operations
        RefreshToken GetByToken(string token);
        IEnumerable<RefreshToken> GetByUserId(Guid userId);

        // Asynchronous operations
        Task<RefreshToken> GetByTokenAsync(string token);
        Task<IEnumerable<RefreshToken>> GetByUserIdAsync(Guid userId);
    }
}
