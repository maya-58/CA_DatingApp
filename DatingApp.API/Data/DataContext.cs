using Microsoft.EntityFrameworkCore;
using DatingApp.API.Models;

namespace DatingApp.API.Data
{
    public class DataContext : DbContext
    {
        //Create a constructor
        public DataContext(DbContextOptions<DataContext> options): base(options){}

        //Refer to Model as a Db context
        public DbSet<Value> Values{get;set;}

        public DbSet<User> Users{get;set;}
    }
}