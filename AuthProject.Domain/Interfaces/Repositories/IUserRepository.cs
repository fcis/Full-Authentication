using AuthProject.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Repositories
{
    public interface IUserRepository : IRepository<User>
    {
        // Synchronous operations
        User GetByEmail(string email);
        User GetByUsername(string username);
        bool EmailExists(string email);
        bool UsernameExists(string username);

        // Asynchronous operations
        Task<User> GetByEmailAsync(string email);
        Task<User> GetByUsernameAsync(string username);
        Task<bool> EmailExistsAsync(string email);
        Task<bool> UsernameExistsAsync(string username);
    }
}
