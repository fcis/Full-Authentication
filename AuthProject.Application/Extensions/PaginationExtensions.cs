// AuthProject.Application/Extensions/PaginationExtensions.cs
using AuthProject.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthProject.Application.Extensions
{
    public static class PaginationExtensions
    {
        public static PagedResult<T> ToPagedResult<T>(this IQueryable<T> source, int pageNumber, int pageSize)
        {
            var totalCount = source.Count();
            var items = source.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToList();

            return new PagedResult<T>(items, totalCount, pageNumber, pageSize);
        }

        public static PagedResult<T> ToPagedResult<T>(this IEnumerable<T> source, int pageNumber, int pageSize)
        {
            return source.AsQueryable().ToPagedResult(pageNumber, pageSize);
        }

        public static async Task<PagedResult<T>> ToPagedResultAsync<T>(this IQueryable<T> source, int pageNumber, int pageSize)
        {
            var totalCount = await Task.FromResult(source.Count());
            var items = await Task.FromResult(source.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToList());

            return new PagedResult<T>(items, totalCount, pageNumber, pageSize);
        }
    }
}