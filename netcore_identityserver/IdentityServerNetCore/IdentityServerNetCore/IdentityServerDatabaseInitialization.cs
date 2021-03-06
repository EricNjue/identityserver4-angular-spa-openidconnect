﻿using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerNetCore
{
    public static class IdentityServerDatabaseInitialization
    {
        public static void InitializeDatabase(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices
                                         .GetService<IServiceScopeFactory>()
                                         .CreateScope())
            {
                PerformMigrations(serviceScope);
                SeedData(serviceScope);
            }
        }

        private static void PerformMigrations(IServiceScope serviceScope)
        {
            serviceScope.ServiceProvider
                        .GetRequiredService<ConfigurationDbContext>()
                        .Database
                        .Migrate();
            serviceScope.ServiceProvider
                        .GetRequiredService<PersistedGrantDbContext>()
                        .Database
                        .Migrate();

            serviceScope.ServiceProvider
                        .GetRequiredService<ApplicationDbContext>()
                        .Database
                        .Migrate();
        }

        private static void SeedData(IServiceScope serviceScope)
        {
            var context = serviceScope
                           .ServiceProvider
                           .GetRequiredService<ConfigurationDbContext>();

            if (!context.Clients.Any())
            {
                foreach (var client in Clients.Get())
                {
                    context.Clients.Add(client.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.IdentityResources.Any())
            {
                foreach (var resource in Resources.GetIdentityResources())
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.ApiResources.Any())
            {
                foreach (var resource in Resources.GetApiResources())
                {
                    context.ApiResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
        }
    }
}
