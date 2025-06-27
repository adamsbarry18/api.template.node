import 'reflect-metadata';
import { DataSource, type DataSourceOptions } from 'typeorm';

import config from '@/config';
import { User } from '@/modules/users';

export const appDataSourceOptions: DataSourceOptions = {
  type: config.DB_TYPE,
  host: config.DB_HOST,
  port: config.DB_PORT,
  username: config.DB_USERNAME,
  password: config.DB_PASSWORD,
  database: config.DB_NAME,
  synchronize: config.DB_SYNCHRONIZE,
  logging: ['error'],
  entities: [User],
  migrations: [],
  subscribers: [],
};

export const appDataSource = new DataSource(appDataSourceOptions);
