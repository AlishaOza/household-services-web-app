from sqlalchemy_schemadisplay import create_schema_graph
from sqlalchemy import MetaData
from sqlalchemy import create_engine

# Define the SQLite connection string (path to your db.sqlite file)
engine = create_engine('sqlite:///instance/db.sqlite')

# Create a MetaData object to hold information about the schema
metadata = MetaData()

# Reflect the existing database schema into the MetaData object
metadata.reflect(bind=engine)

print(metadata.tables.keys())
# Create the schema graph
graph = create_schema_graph(engine,
    metadata=metadata,
    show_datatypes=True,  # Show column datatypes
    show_indexes=True,    # Show indexes on columns
    rankdir='LR',         # Left-to-right layout
    concentrate=False     # Do not merge edges
)

# Save the graph to a file (e.g., schema.png)
graph.write_png('docs/schema.png')
