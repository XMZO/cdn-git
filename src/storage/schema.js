"use strict";

const { z } = require("zod");

const PortSchema = z.number().int().min(1).max(65535);

const PortsSchema = z.object({
  admin: PortSchema.default(3100),
  torcherino: PortSchema.default(3000),
  cdnjs: PortSchema.default(3001),
  git: PortSchema.default(3002),
});

const RedisSchema = z.object({
  host: z.string().min(1).default("redis"),
  port: PortSchema.default(6379),
});

const CdnjsSchema = z.object({
  assetUrl: z.string().url().default("https://cdn.jsdelivr.net"),
  allowedGhUsers: z.array(z.string().min(1)).default([]),
  defaultGhUser: z.string().default(""),
  redis: RedisSchema.default({ host: "redis", port: 6379 }),
});

const GitSchema = z.object({
  githubToken: z.string().default(""),
  githubAuthScheme: z.enum(["token", "Bearer"]).default("token"),

  upstream: z.string().min(1).default("raw.githubusercontent.com"),
  upstreamMobile: z.string().min(1).default("raw.githubusercontent.com"),
  upstreamPath: z.string().min(1).default("/XMZO/pic/main"),
  https: z.boolean().default(true),

  disableCache: z.boolean().default(false),
  cacheControl: z.string().default(""),
  cacheControlMedia: z.string().default("public, max-age=43200000"),
  cacheControlText: z.string().default("public, max-age=60"),

  corsOrigin: z.string().default("*"),
  corsAllowCredentials: z.boolean().default(false),
  corsExposeHeaders: z
    .string()
    .default(
      "Accept-Ranges, Content-Length, Content-Range, ETag, Cache-Control, Last-Modified"
    ),

  blockedRegions: z.array(z.string().min(1)).default([]),
  blockedIpAddresses: z.array(z.string().min(1)).default(["0.0.0.0", "127.0.0.1"]),

  replaceDict: z.record(z.string()).default({ $upstream: "$custom_domain" }),
});

const TorcherinoSchema = z.object({
  defaultTarget: z.string().default(""),
  hostMapping: z.record(z.string()).default({}),
  workerSecretKey: z.string().default(""),
  workerSecretHeaders: z.array(z.string().min(1)).default([]),
  workerSecretHeaderMap: z.record(z.string()).default({}),
});

const AppConfigSchema = z.object({
  version: z.literal(1).default(1),
  ports: PortsSchema.default({
    admin: 3100,
    torcherino: 3000,
    cdnjs: 3001,
    git: 3002,
  }),
  cdnjs: CdnjsSchema.default({}),
  git: GitSchema.default({}),
  torcherino: TorcherinoSchema.default({}),
});

module.exports = { AppConfigSchema };

