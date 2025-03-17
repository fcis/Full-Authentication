using AuthProject.Domain.Interfaces.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        // Repositories
        IUserRepository Users { get; }
        IUserTokenRepository UserTokens { get; }
        IRefreshTokenRepository RefreshTokens { get; }

        // Synchronous operations
        int SaveChanges();
        void BeginTransaction();
        void Commit();
        void Rollback();

        // Asynchronous operations
        Task<int> SaveChangesAsync();
        Task BeginTransactionAsync();
        Task CommitAsync();
        Task RollbackAsync();
    }
}
