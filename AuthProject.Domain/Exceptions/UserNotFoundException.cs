using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Exceptions
{
    public class UserNotFoundException : DomainException
    {
        public UserNotFoundException(string identifier)
            : base($"User with identifier {identifier} was not found.") { }
    }
}
