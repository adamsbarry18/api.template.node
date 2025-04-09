import 'reflect-metadata';
import { DataSource, DataSourceOptions } from 'typeorm';
import config from '@/config';
import path from 'path';

export const AppDataSourceOptions: DataSourceOptions = {
  type: config.DB_TYPE,
  host: config.DB_HOST,
  port: config.DB_PORT,
  username: config.DB_USERNAME,
  password: config.DB_PASSWORD,
  database: config.DB_DATABASE,
  synchronize: config.DB_SYNCHRONIZE,
  logging: ['error'],
  entities: [path.join(__dirname, '../modules/**/*.entity{.js,.ts}')],
  migrations: [path.join(__dirname, './migrations/*{.js,.ts}')],
  subscribers: [],
  // namingStrategy: new SnakeNamingStrategy(), // Si besoin
};

export const AppDataSource = new DataSource(AppDataSourceOptions);
