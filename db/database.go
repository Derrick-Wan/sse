package postgresmodule

import (
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
)

type Dcount struct {
	Keyword string `pg:",pk"`
	Count   int
}

type D struct {
	L string `pg:",pk"`
	D string
}

type PostgresModule struct {
	db *pg.DB
}

func NewPostgresModule(connectionString string) (*PostgresModule, error) {
	opt, err := pg.ParseURL(connectionString)
	if err != nil {
		return nil, err
	}

	db := pg.Connect(opt)

	return &PostgresModule{db: db}, nil
}

func (p *PostgresModule) Close() {
	p.db.Close()
}

func (p *PostgresModule) InsertOrUpdateDcount(keyword string, count int) error {
	dcount := Dcount{
		Keyword: keyword,
		Count:   count,
	}

	_, err := p.db.Model(&dcount).
		OnConflict("(keyword) DO UPDATE").
		Insert()

	return err
}

func (p *PostgresModule) GetDcount(keyword string) (int, error) {
	var dcount Dcount
	err := p.db.Model(&dcount).
		Where("keyword = ?", keyword).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return 0, nil // Keyword not found
		}
		return 0, err
	}

	return dcount.Count, nil
}

func (p *PostgresModule) InsertOrUpdateD(l string, d string) error {
	dData := D{
		L: l,
		D: d,
	}

	_, err := p.db.Model(&dData).
		OnConflict("(l) DO UPDATE").
		Insert()

	return err
}

func (p *PostgresModule) GetD(l string) (string, error) {
	var dData D
	err := p.db.Model(&dData).
		Where("l = ?", l).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return "", nil // Key not found
		}
		return "", err
	}

	return dData.D, nil
}

func CreateSchema(db *pg.DB) error {
	models := []interface{}{
		(*Dcount)(nil),
		(*D)(nil),
	}

	for _, model := range models {
		err := db.Model(model).CreateTable(&orm.CreateTableOptions{
			Temp:          false,
			FKConstraints: true,
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func SetupDatabase() (*PostgresModule, error) {
	connectionString := "postgres://yourusername:yourpassword@localhost:5432/yourdb"
	module, err := NewPostgresModule(connectionString)
	if err != nil {
		return nil, err
	}

	err = CreateSchema(module.db)
	if err != nil {
		module.Close()
		return nil, err
	}

	return module, nil
}
