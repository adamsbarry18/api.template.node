import 'reflect-metadata';
import { DataSource, type DataSourceOptions } from 'typeorm';

import config from '@/config';
import { User } from '@/modules/users/models/users.entity';

export const appDataSourceOptions: DataSourceOptions = {
  type: config.DB_TYPE,
  host: config.DB_HOST,
  port: config.DB_PORT,
  username: config.DB_USERNAME,
  password: config.DB_PASSWORD,
  database: config.DB_NAME,
  synchronize: false,
  logging: ['error'],
  // Use glob pattern to automatically find all entities
  entities: [User],
  migrations: [],
  subscribers: [],
  // namingStrategy: new SnakeNamingStrategy(), // Si besoin
};

export const appDataSource = new DataSource(appDataSourceOptions);
