
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace WebApplication1
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers();
            builder.Services.AddOpenApi();

            // ������������ �������������� � ��������� ������ "Ed25519"
            builder.Services.AddAuthentication("Ed25519")
            .AddScheme<AuthenticationSchemeOptions, Ed25519AuthenticationHandler>("Ed25519", options => { });

            // ��� ������� ������� ����������� endpoint, ���������� ���������������
            builder.Services.AddAuthorization();


            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}

