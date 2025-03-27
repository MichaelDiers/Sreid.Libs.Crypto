namespace Sreid.Libs.Crypto.Tests.Streams;

using System.Security.Cryptography;
using Sreid.Libs.Crypto.Aes;
using Sreid.Libs.Crypto.Factory;
using Sreid.Libs.Crypto.Streams;
using Sreid.Libs.Crypto.Tests.Helper;

/// <summary>
///     Tests of <see cref="AesBrotliStream" />.
/// </summary>
public class AesBrotliStreamTests : IDisposable
{
    private readonly ICryptoFactory cryptoFactory =
        DependencyHelper.GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory);

    private MemoryStream? memoryStream;

    [Theory]
    [InlineData(
        AesBrotliStreamMode.Pack,
        false)]
    [InlineData(
        AesBrotliStreamMode.Unpack,
        true)]
    public void CanRead(AesBrotliStreamMode streamMode, bool expectedCanRead)
    {
        using var stream = this.Initialize(streamMode);

        Assert.Equal(
            expectedCanRead,
            stream.CanRead);
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void CanSeek(AesBrotliStreamMode streamMode)
    {
        using var stream = this.Initialize(streamMode);

        Assert.False(stream.CanSeek);
    }

    [Theory]
    [InlineData(
        AesBrotliStreamMode.Pack,
        true)]
    [InlineData(
        AesBrotliStreamMode.Unpack,
        false)]
    public void CanWrite(AesBrotliStreamMode streamMode, bool expectedCanWrite)
    {
        using var stream = this.Initialize(streamMode);

        Assert.Equal(
            expectedCanWrite,
            stream.CanWrite);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Decrypt(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = DependencyHelper
            .GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory)
            .CreateAesService(new AesOptions(aesKeySizeInBits))
            .GenerateAesKey();

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        // encrypt
        using var encryptedMemoryStream = new MemoryStream();
        using (var aesBrotliStream = new AesBrotliStream(
                   encryptedMemoryStream,
                   AesBrotliStreamMode.Pack,
                   aesKey))
        {
            aesBrotliStream.Write(data);
        }

        var encrypted = encryptedMemoryStream.ToArray();
        Assert.True(encrypted.Length > data.Length);

        // decrypt
        using var decryptedMemoryStream = new MemoryStream();
        using var decryptMemoryStream = new MemoryStream(encrypted);
        using (var decryptAesBrotliStream = new AesBrotliStream(
                   decryptMemoryStream,
                   AesBrotliStreamMode.Unpack,
                   aesKey))
        {
            decryptAesBrotliStream.CopyTo(decryptedMemoryStream);
        }

        var decrypted = decryptedMemoryStream.ToArray();
        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(16)]
    public void Decrypt_ShouldFail_DueToInvalidData(int dataLength)
    {
        var aesKey = DependencyHelper
            .GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory)
            .CreateAesService()
            .GenerateAesKey();

        var data = new byte[dataLength];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);
        if (dataLength != 0)
        {
            data[0] = 16;
        }

        // decrypt
        var decryptedMemoryStream = new MemoryStream();
        var decryptMemoryStream = new MemoryStream(data);
        var decryptAesBrotliStream = new AesBrotliStream(
            decryptMemoryStream,
            AesBrotliStreamMode.Unpack,
            aesKey);

        Assert.Throws<InvalidOperationException>(
            () =>
            {
                try
                {
                    decryptAesBrotliStream.CopyTo(decryptedMemoryStream);
                }
                finally
                {
                    decryptAesBrotliStream.Dispose();
                    decryptMemoryStream.Dispose();
                    decryptedMemoryStream.Dispose();
                }
            });
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public async Task DecryptAsync(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = await DependencyHelper
            .GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory)
            .CreateAesService(new AesOptions(aesKeySizeInBits))
            .GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        // encrypt
        using var encryptedMemoryStream = new MemoryStream();
        await using (var aesBrotliStream = new AesBrotliStream(
                         encryptedMemoryStream,
                         AesBrotliStreamMode.Pack,
                         aesKey))
        {
            await aesBrotliStream.WriteAsync(
                data,
                TestContext.Current.CancellationToken);
        }

        var encrypted = encryptedMemoryStream.ToArray();
        Assert.True(encrypted.Length > data.Length);

        // decrypt
        using var decryptedMemoryStream = new MemoryStream();
        using var decryptMemoryStream = new MemoryStream(encrypted);
        await using (var decryptAesBrotliStream = new AesBrotliStream(
                         decryptMemoryStream,
                         AesBrotliStreamMode.Unpack,
                         aesKey))
        {
            await decryptAesBrotliStream.CopyToAsync(
                decryptedMemoryStream,
                TestContext.Current.CancellationToken);
        }

        var decrypted = decryptedMemoryStream.ToArray();
        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    /// <summary>
    ///     Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    public void Dispose()
    {
        this.memoryStream?.Dispose();
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Encrypt(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = DependencyHelper
            .GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory)
            .CreateAesService(new AesOptions(aesKeySizeInBits))
            .GenerateAesKey();

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        using var encryptedMemoryStream = new MemoryStream();
        using (var aesBrotliStream = new AesBrotliStream(
                   encryptedMemoryStream,
                   AesBrotliStreamMode.Pack,
                   aesKey))
        {
            aesBrotliStream.Write(data);
        }

        var encrypted = encryptedMemoryStream.ToArray();
        Assert.True(encrypted.Length > data.Length);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public async Task EncryptAsync(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = await DependencyHelper
            .GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory)
            .CreateAesService(new AesOptions(aesKeySizeInBits))
            .GenerateAesKeyAsync(TestContext.Current.CancellationToken);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        using var encryptedMemoryStream = new MemoryStream();
        await using (var aesBrotliStream = new AesBrotliStream(
                         encryptedMemoryStream,
                         AesBrotliStreamMode.Pack,
                         aesKey))
        {
            await aesBrotliStream.WriteAsync(
                data,
                TestContext.Current.CancellationToken);
        }

        var encrypted = encryptedMemoryStream.ToArray();
        Assert.True(encrypted.Length > data.Length);
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void Flush(AesBrotliStreamMode streamMode)
    {
        using var stream = this.Initialize(streamMode);

        stream.Flush();
    }

    [Fact]
    public void Flush_AfterWrite()
    {
        var aesKey = this.cryptoFactory.CreateAesService().GenerateAesKey();

        using var encryptedStream = new MemoryStream();
        using var aesBrotliStream = new AesBrotliStream(
            encryptedStream,
            AesBrotliStreamMode.Pack,
            aesKey);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        aesBrotliStream.Write(data);
        aesBrotliStream.Write(
            data,
            1,
            2);

        aesBrotliStream.Flush();

        var encrypted = encryptedStream.ToArray();
        Assert.NotNull(encrypted);
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void Length(AesBrotliStreamMode streamMode)
    {
        var stream = this.Initialize(streamMode);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    return stream.Length;
                }
                finally
                {
                    stream.Dispose();
                }
            });
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void Position_Get(AesBrotliStreamMode streamMode)
    {
        var stream = this.Initialize(streamMode);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    return stream.Position;
                }
                finally
                {
                    stream.Dispose();
                }
            });
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void Position_Set(AesBrotliStreamMode streamMode)
    {
        var stream = this.Initialize(streamMode);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    stream.Position = 10;
                }
                finally
                {
                    stream.Dispose();
                }
            });
    }

    [Fact]
    public void Read_Pack_ShouldFail()
    {
        var stream = this.Initialize(AesBrotliStreamMode.Pack);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    var buffer = new byte[10];
                    _ = stream.Read(buffer);
                }
                finally
                {
                    stream.Dispose();
                }
            });
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Read_Unpack(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = DependencyHelper
            .GetRequiredService<ICryptoFactory>(FactoryServiceCollectionExtensions.TryAddCryptoFactory)
            .CreateAesService(new AesOptions(aesKeySizeInBits))
            .GenerateAesKey();

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        // encrypt
        using var encryptedMemoryStream = new MemoryStream();
        using (var aesBrotliStream = new AesBrotliStream(
                   encryptedMemoryStream,
                   AesBrotliStreamMode.Pack,
                   aesKey))
        {
            aesBrotliStream.Write(data);
        }

        var encrypted = encryptedMemoryStream.ToArray();
        Assert.True(encrypted.Length > data.Length);

        // decrypt
        var decrypted = new byte[data.Length];
        using var decryptMemoryStream = new MemoryStream(encrypted);
        using (var decryptAesBrotliStream = new AesBrotliStream(
                   decryptMemoryStream,
                   AesBrotliStreamMode.Unpack,
                   aesKey))
        {
            var totalRead = 0;
            while (totalRead != decrypted.Length)
            {
                var actualLength = decryptAesBrotliStream.Read(
                    decrypted,
                    totalRead,
                    decrypted.Length - totalRead);

                if (actualLength == 0)
                {
                    break;
                }

                totalRead += actualLength;
            }
        }

        Assert.True(
            data.Length == decrypted.Length &&
            Enumerable.Range(
                    0,
                    data.Length)
                .All(index => data[index] == decrypted[index]));
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void Seek(AesBrotliStreamMode streamMode)
    {
        var stream = this.Initialize(streamMode);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    stream.Seek(
                        10,
                        SeekOrigin.Begin);
                }
                finally
                {
                    stream.Dispose();
                }
            });
    }

    [Theory]
    [InlineData(AesBrotliStreamMode.Pack)]
    [InlineData(AesBrotliStreamMode.Unpack)]
    public void SetLength(AesBrotliStreamMode streamMode)
    {
        var stream = this.Initialize(streamMode);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    stream.SetLength(10);
                }
                finally
                {
                    stream.Dispose();
                }
            });
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Write_Pack(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits)).GenerateAesKey();

        using var encryptedStream = new MemoryStream();
        using var aesBrotliStream = new AesBrotliStream(
            encryptedStream,
            AesBrotliStreamMode.Pack,
            aesKey);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        aesBrotliStream.Write(data);
        aesBrotliStream.Write(
            data,
            1,
            2);

        var encrypted = encryptedStream.ToArray();
        Assert.NotNull(encrypted);
    }

    [Theory]
    [InlineData(AesKeySizeInBits.KeySize128)]
    [InlineData(AesKeySizeInBits.KeySize192)]
    [InlineData(AesKeySizeInBits.KeySize256)]
    public void Write_Unpack(AesKeySizeInBits aesKeySizeInBits)
    {
        var aesKey = this.cryptoFactory.CreateAesService(new AesOptions(aesKeySizeInBits)).GenerateAesKey();

        using var encryptedStream = new MemoryStream();
        var aesBrotliStream = new AesBrotliStream(
            encryptedStream,
            AesBrotliStreamMode.Unpack,
            aesKey);

        var data = new byte[16];
        RandomNumberGenerator.Create().GetNonZeroBytes(data);

        Assert.Throws<NotSupportedException>(
            () =>
            {
                try
                {
                    aesBrotliStream.Write(data);
                }
                finally
                {
                    aesBrotliStream.Dispose();
                }
            });
    }

    private AesBrotliStream Initialize(AesBrotliStreamMode aesBrotliStreamMode)
    {
        this.memoryStream = new MemoryStream();
        return new AesBrotliStream(
            this.memoryStream,
            aesBrotliStreamMode,
            []);
    }
}
