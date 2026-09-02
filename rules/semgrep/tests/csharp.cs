// Fixture testowy reguł „nigdy" dla C#.
// Uruchomienie: semgrep --test --config rules/semgrep rules/semgrep/tests

using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;

class Demo
{
    void TlsDisabled()
    {
        // ruleid: no-tls-verify-disabled-cs
        ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, errors) => true;
    }

    void TlsDisabledHandler(HttpClientHandler handler)
    {
        // ruleid: no-tls-verify-disabled-cs
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
    }

    void TlsOk(HttpClientHandler handler)
    {
        // ok: no-tls-verify-disabled-cs
        handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => c.Verify();
    }

    void SqlConcat(SqlConnection conn, string userId)
    {
        // ruleid: no-sql-string-concat-cs
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id=" + userId, conn);
    }

    void SqlInterpolated(SqlConnection conn, string userId)
    {
        // ruleid: no-sql-string-concat-cs
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id={userId}", conn);
    }

    void SqlParametrized(SqlConnection conn, string userId)
    {
        // ok: no-sql-string-concat-cs
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id=@id", conn);
        cmd.Parameters.AddWithValue("@id", userId);
    }

    void ShellInterpolated(string userInput)
    {
        // ruleid: no-shell-true-cs
        Process.Start($"cmd.exe /c {userInput}");
    }

    void ShellArguments(string userInput)
    {
        // ruleid: no-shell-true-cs
        var psi = new ProcessStartInfo("cmd.exe") { Arguments = $"/c {userInput}" };
    }

    void ShellArgumentList(string userInput)
    {
        // ok: no-shell-true-cs
        var psi = new ProcessStartInfo("cmd.exe");
        psi.ArgumentList.Add("/c");
        psi.ArgumentList.Add(userInput);
        Process.Start(psi);
    }

    void DeserializeChained(System.IO.Stream data)
    {
        // ruleid: no-unsafe-deserialization-cs
        var obj = new BinaryFormatter().Deserialize(data);
    }

    void DeserializeVariable(System.IO.Stream data)
    {
        // ruleid: no-unsafe-deserialization-cs
        var bf = new BinaryFormatter();
        var obj = bf.Deserialize(data);
    }

    void DeserializeOk(string json)
    {
        // ok: no-unsafe-deserialization-cs
        var obj = System.Text.Json.JsonSerializer.Deserialize<object>(json);
    }
}
