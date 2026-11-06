using System.Security.Cryptography;
using System.Text;
using Auth.Local.Api.Data;
using Auth.Local.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace Auth.Local.Api.Auth;

public record TokenPair(string AccessToken, string RefreshToken);

public class RefreshTokenService(AppDbContext db, TokenService tokens)
{
    private static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(7);

    // SHA-256 en hexadecimal (64 caracteres). Es lo único que se guarda en la BD.
    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    // 64 bytes aleatorios criptográficamente seguros (el mínimo pedido es 32).
    private static string GenerateToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private (RefreshToken Entity, string Plain) CreateEntity(User user)
    {
        var plain = GenerateToken();
        var now = DateTime.UtcNow;
        var entity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = Hash(plain),
            CreatedAt = now,
            ExpiresAt = now.Add(RefreshLifetime),
        };
        db.RefreshTokens.Add(entity);
        return (entity, plain);
    }

    /// <summary>Emite un par nuevo (login y verificación 2FA).</summary>
    public async Task<TokenPair> IssueAsync(User user)
    {
        var (_, plain) = CreateEntity(user);
        await db.SaveChangesAsync();
        return new TokenPair(tokens.CreateAccessToken(user), plain);
    }

    /// <summary>
    /// Rotación: valida el refresh token, lo revoca y entrega un par nuevo.
    /// Devuelve null si no es válido (el endpoint responde 401).
    /// </summary>
    public async Task<TokenPair?> RotateAsync(string? presented)
    {
        if (string.IsNullOrWhiteSpace(presented))
            return null;

        var hash = Hash(presented);
        var stored = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash);
        if (stored is null)
            return null;

        var now = DateTime.UtcNow;

        // DETECCIÓN DE REUTILIZACIÓN: un token ya revocado volvió a aparecer.
        // Puede que alguien lo robó; no sabemos quién es el legítimo, así que
        // revocamos TODOS los tokens activos del usuario (debe iniciar sesión de nuevo).
        if (stored.RevokedAt is not null)
        {
            var activos = await db.RefreshTokens
                .Where(t => t.UserId == stored.UserId && t.RevokedAt == null)
                .ToListAsync();
            foreach (var t in activos)
                t.RevokedAt = now;
            await db.SaveChangesAsync();
            return null;
        }

        if (stored.ExpiresAt <= now)
            return null;

        var user = await db.Users.FindAsync(stored.UserId);
        if (user is null)
            return null;

        // ROTACIÓN: el token usado queda revocado y enlazado a su reemplazo.
        var (nuevo, plain) = CreateEntity(user);
        stored.RevokedAt = now;
        stored.ReplacedByTokenId = nuevo.Id;
        await db.SaveChangesAsync();

        return new TokenPair(tokens.CreateAccessToken(user), plain);
    }

    /// <summary>Logout: revoca el refresh token recibido (si existe y está activo).</summary>
    public async Task RevokeAsync(string? presented)
    {
        if (string.IsNullOrWhiteSpace(presented))
            return;

        var hash = Hash(presented);
        var stored = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash);
        if (stored is { RevokedAt: null })
        {
            stored.RevokedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
    }
}