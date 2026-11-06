namespace Auth.Local.Api.Models;

/// <summary>
/// Refresh token de larga duración (7 días). En la BD se guarda SOLO su hash SHA-256:
/// si roban la base, no pueden usar los tokens. El valor original solo lo ve el cliente.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; }
    public int UserId { get; set; }
    public required string TokenHash { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    // Token que lo reemplazó al rotar (cadena de rotación, útil para auditoría).
    public Guid? ReplacedByTokenId { get; set; }
}