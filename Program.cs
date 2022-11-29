using System.Security.Cryptography;
using System.Text;

const int keySize = 64;
const int iterations = 350000;
HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;

if (Environment.GetCommandLineArgs().Length != 2)
{
    Console.WriteLine("Usage: HashingAndSaltingPasswords <password>\nYou must specify the password for encryption.\n");
    return;
}

var password = Environment.GetCommandLineArgs()[1];

var hash = HashPasword(password, out var salt);

Console.WriteLine($"Password hash: {hash}");
Console.WriteLine($"Generated salt: {Convert.ToHexString(salt)}");

var verificationResult = VerifyPassword(password, hash, salt);
Console.WriteLine($"Password verification: {verificationResult}");

string HashPasword(string password, out byte[] salt)
{
    salt = RandomNumberGenerator.GetBytes(keySize);

    var hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(password),
        salt,
        iterations,
        hashAlgorithm,
        keySize);

    return Convert.ToHexString(hash);
        }

bool VerifyPassword(string password, string hash, byte[] salt)
{
    var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);

    return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
}
