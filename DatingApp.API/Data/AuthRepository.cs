
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;


namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
           private readonly DataContext _context;
        public AuthRepository(DataContext context)
        {
            _context=context;
            
        }
        public async Task<User> Login(string username,string password){

            var user=await _context.Users.FirstOrDefaultAsync(x => x.Username == username);

            if(user == null)
                return null;

            if(!VerifyPasswordHash(password,user.PasswordHash,user.PasswordSalt))
                return user;
              
              
            return user;

            ///throw new System.NotFiniteNumberException();
        }

        private bool VerifyPasswordHash(string password,byte[] PasswordHash,byte[] PasswordSalt)
        {
            using(var hmac=new System.Security.Cryptography.HMACSHA512(PasswordSalt))
            {
                //PasswordSalt=hmac.Key;
                var ComputeHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                for(int i=0 ; i <ComputeHash.Length ;i++){
                    if(ComputeHash[i] != PasswordHash[i]) return false;

                }
            }

            return true;

        }



        public async Task<User> Register(User user,string password){
            //throw new System.NotFiniteNumberException();

            byte[] PasswordHash,PasswordSalt;
            CreatePasswordHash(password,out PasswordHash,out PasswordSalt);


            //Adding values to User Object after Hashing
            user.PasswordHash=PasswordHash;
            user.PasswordSalt=PasswordSalt;


            //Saving to Database
            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            return user;

        }

        private void CreatePasswordHash(string password,out byte[] PasswordHash,out byte[] PasswordSalt){


            using(var hmac=new System.Security.Cryptography.HMACSHA512())
            {
                PasswordSalt=hmac.Key;
                PasswordHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
  
        }


        public async Task<bool> UserExists(string username){

            if(await _context.Users.AnyAsync(x => x.Username == username))
                return true;

            return false;
            //throw new System.NotFiniteNumberException();
        }
    }
}