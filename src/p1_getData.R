# Visual Analysis of Cyber Threat. Part 1: Acquiring the data
# Serhan Aya 2016-06-30.

# In this part, using the following packages the virus information
# data is acquired from the Avira web site and saved as a
# dataframe.

# Load required packages
library(rvest)     # Web scraping
library(magrittr)  # Data manipulation
library(plyr)      # Data manipulation
library(tidyr)     # Data manipulation
library(dplyr)     # Data manipulation
library(feather)   # Save/load dataframe

# Set main page.
homepage <- read_html("https://www.avira.com/en/support-virus-lab")

# Extract the link to the last page of Virus Descriptions page.
lastPageURL <- homepage %>%    # Feed `homepage` to the next step
    html_nodes(".last a") %>%  # Get the CSS nodes
    html_attr("href")          # Extract the URLs

# Get the last page number.
lastPageNum <- as.numeric(gsub("[^0-9]", "", unlist(lastPageURL)))

# Generate URLs that have virus information.
urls <- c()
for (pageNum in 1:lastPageNum) {
    urls[pageNum] <- paste0("https://www.avira.com/en/support-virus-lab?vdl[currentPage]=",
                            pageNum, "&vdl[sq]=&vdl[first]=")
}

# Following function reads the table from generated URLs.
# Additionally follows the link provided for each virus name
# and gets the details for these viruses.
readUrl <- function(url) {
    ## Virus Descriptions Main Table ##

    html <- read_html(url)
    tVir <- html %>%
        html_table(fill = TRUE)
    tVir <- tVir[[1]]

    ## Virus Details ##

    # Follow links on each virus name.
    virLinks <- read_html(url) %>%
        html_nodes(".td-title a") %>%
        html_text(trim=TRUE)

    # Generate links to virus details.
    virDefUrls <- c()
    for (virNum in 1:length(virLinks)) {

        node <- paste0("tr:nth-child(",virNum,") a")

        subLink <- read_html(url) %>%
            html_nodes(node) %>%
            html_attr("href")

        virDefUrls[virNum] <- paste0("https://www.avira.com", subLink)
    }

    # The following function reads the information (as a table)
    # on the virus details pages. Some of the pages are not available,
    # In order to avoid the reading errors, `tryCatch` block  is used.
    readVirDef <- function(virDefUrl) {
        out <- tryCatch(
            {
                # vol1 consist of properties of the viruses in details page.
                col1 <- read_html(virDefUrl) %>%
                    html_nodes(".list-title") %>%
                    html_text(trim=TRUE)
                # col2 consist of values of the pertinent properties in details page.
                col2 <- read_html(virDefUrl) %>%
                    html_nodes(".list-content") %>%
                    html_text(trim=TRUE)

                # Create a dataframe using obtained property names and their values of
                # a specific virus.
                tempVirDef <- data.frame(Attr1=col1, Attr2=col2, stringsAsFactors = FALSE)
                # Change the columns with rows using tidyr's spread command.
                tempVirDef <- spread(tempVirDef, Attr1, Attr2)
            },
            error=function(cond) {
                message(paste("Error in:", virDefUrl))
                message(cond)
            },
            warning=function(cond) {
                message(paste("Warning in:", virDefUrl))
                message(cond)
            },
            finally={
                message(paste("Processed URL:", virDefUrl))
            }
        )
        return(out)
    }
    # Apply readVirDef function to all virus names listed in opened page.
    y1 <- lapply(virDefUrls, readVirDef)
    # Create dataframe from previous list.
    tVirDef <- do.call(rbind.fill, y1)
    # Join main virus table (dataframe) with the virus details table (dataframe)
    tVirFull <- left_join(tVir, tVirDef, by="Name")
}

# Apply readUrl function to the generated URLs. This function will get all the tables
# in the available pages in virus definitions page. It will get the names of the Viruses
# and follow the links in each page for the detailed information. Afterwards, the two tables,
# namely "main table" and "details table" will be joined. The result is a list.
y <- lapply(urls, readUrl)
# the resulting list will be row binded into a dataframe.
tVirData <- rbind_all(y)

# Deleting additional columns that are not related to the analysis
# and are added on some of the pages with the chosen CSS nodes.
tVirData <- tVirData %>%
    select(-c(4, 10, 14:17))

# Assign the column names.
names(tVirData) <- c("No", "Name", "Type", "AddedOn", "DateDiscovered",
                     "Impact", "OS", "Infections", "VDF", "VDFver", "Aliases")

# Some of the columns are suspicious because of the similarity.
identical(tVirData$VDF, tVirData$VDFver)
# TRUE

# Remove one of these identical columns.
tVirData <- tVirData %>%
    select(-VDFver)

# Another two will be checked for similarity.
identical(tVirData$AddedOn, tVirData$DateDiscovered)
# FALSE
# Even the answer is FALSE, similarity will be checked again.
# Investigation will be focused on this: class() of this column
# is date, not character.

# Save the dataframe for later use.
path <- "data/tVirData.feather"
write_feather(tVirData, path)
