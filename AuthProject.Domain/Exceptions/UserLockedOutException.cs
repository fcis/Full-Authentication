using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Exceptions
{
    public class UserLockedOutException : DomainException
    {
        public UserLockedOutException(DateTime lockoutEnd)
            : base($"User is locked out until {lockoutEnd}.") { }
    }
}
