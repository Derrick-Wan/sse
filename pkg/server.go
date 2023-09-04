package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Derrick-Wan/sse/pkg/postgresmodule"
)

type Dcount struct {
	Keyword string
	Count   int
}

type D struct {
	L string
	D string
}

func main() {

	module, err := postgresmodule.SetupDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer module.Close()

	r := gin.Default()

	r.POST("/getDcount", func(c *gin.Context) {
		var input struct {
			Keyword string `json:"keyword"`
		}
		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var result Dcount
		count, err := module.GetDcount(input.Keyword)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Dcount:", count)
		result.Keyword = input.Keyword
		result.Count = count

		c.JSON(http.StatusOK, result)
	})

	r.POST("/UpdateDcount", func(c *gin.Context) {
		var input struct {
			Keyword  string `json:"keyword"`
			CountAdd int    `json:"countadd"`
		}
		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err = module.UpdateCount(input.Keyword, input.CountAdd)
		if err != nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Success"})
	})

	r.POST("/getD", func(c *gin.Context) {
		var input struct {
			L string `json:"l"`
		}
		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var result D
		d, err := module.GetD(input.L)

		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("D:", d)
		result.L = input.L
		result.D = d
		c.JSON(http.StatusOK, result)
	})

	r.POST("/UpdateD", func(c *gin.Context) {
		var input D
		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err = module.InsertOrUpdateD(input.L, input.D)

		if err != nil {
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, gin.H{"message": "Success"})
	})

	r.Run(":8080")

}
